package cmd

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/core"
	"github.com/wyx2685/v2node/limiter"
	"github.com/wyx2685/v2node/machine"
	"github.com/wyx2685/v2node/node"
)

const (
	// revokeAfter 连续收到这么多次 404 才认定凭据已吊销，避免面板短暂异常导致停机。
	revokeAfter = 3
	// retryInterval 尚未拿到配置或已停止时的重试间隔。
	retryInterval = 10 * time.Second
	minPull       = 10 * time.Second
	defaultPull   = 60 * time.Second
)

func setLogLevel(level string) {
	switch level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn", "warning":
		log.SetLevel(log.WarnLevel)
	case "error", "none":
		log.SetLevel(log.ErrorLevel)
	}
}

// nodeRuntime 单个节点的独立运行时封装（V2Core + Controller），便于单节点热重载与测试替身注入。
type nodeRuntime interface {
	Start(nc conf.NodeConfig, logCfg conf.LogConfig, reloadCh chan struct{}) error
	Close() error
}

type xrayNodeRuntime struct {
	v2core *core.V2Core
	ctrl   *node.Controller
}

func newXrayRuntime(_ int) nodeRuntime { return &xrayNodeRuntime{} }

func (r *xrayNodeRuntime) Start(nc conf.NodeConfig, logCfg conf.LogConfig, reloadCh chan struct{}) error {
	c := conf.New()
	c.LogConfig = logCfg
	c.NodeConfigs = []conf.NodeConfig{nc}

	p, err := panel.New(&nc)
	if err != nil {
		return err
	}
	info, err := p.GetNodeInfo(context.Background())
	if err != nil {
		return err
	}
	v2core := core.New(c)
	v2core.ReloadCh = reloadCh
	if err := v2core.Start([]*panel.NodeInfo{info}); err != nil {
		_ = v2core.Close()
		return err
	}
	ctrl := node.NewController(p, &nc, info)
	if err := ctrl.Start(v2core); err != nil {
		_ = ctrl.Close()
		_ = v2core.Close()
		return err
	}
	r.v2core = v2core
	r.ctrl = ctrl
	return nil
}

func (r *xrayNodeRuntime) Close() error {
	var firstErr error
	if r.ctrl != nil {
		if err := r.ctrl.Close(); err != nil {
			firstErr = err
		}
		r.ctrl = nil
	}
	if r.v2core != nil {
		if err := r.v2core.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		r.v2core = nil
	}
	return firstErr
}

// nodeHandle 节点机模式下单个节点的隔离生命周期：独占 V2Core、Controller 与 reloadCh。
type nodeHandle struct {
	nodeID   int
	nc       conf.NodeConfig
	reloadCh chan struct{}
	stopCh   chan struct{}
	doneCh   chan struct{}

	mu     sync.Mutex
	logCfg conf.LogConfig
	rt     nodeRuntime
	active atomic.Bool
}

func startNodeHandle(nc conf.NodeConfig, logCfg conf.LogConfig, factory func(int) nodeRuntime) (*nodeHandle, error) {
	if factory == nil {
		factory = newXrayRuntime
	}
	reloadCh := make(chan struct{}, 1)
	rt := factory(nc.NodeID)
	if err := rt.Start(nc, logCfg, reloadCh); err != nil {
		_ = rt.Close()
		return nil, err
	}
	h := &nodeHandle{
		nodeID:   nc.NodeID,
		nc:       nc,
		logCfg:   logCfg,
		reloadCh: reloadCh,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
		rt:       rt,
	}
	h.active.Store(true)
	go h.watchReload(factory)
	return h, nil
}

func (h *nodeHandle) alive() bool { return h.active.Load() }

func (h *nodeHandle) setLogCfg(logCfg conf.LogConfig) {
	h.mu.Lock()
	h.logCfg = logCfg
	h.mu.Unlock()
}

func (h *nodeHandle) getLogCfg() conf.LogConfig {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.logCfg
}

func (h *nodeHandle) watchReload(factory func(int) nodeRuntime) {
	defer close(h.doneCh)
	for {
		select {
		case <-h.stopCh:
			return
		case <-h.reloadCh:
			log.Infof("节点 #%d 收到重载信号，正在独立重启...", h.nodeID)
			if h.rt != nil {
				if err := h.rt.Close(); err != nil {
					log.WithField("err", err).Errorf("节点 #%d 关闭旧实例失败", h.nodeID)
				}
				h.rt = nil
			}
			select {
			case <-h.stopCh:
				return
			default:
			}
			next := factory(h.nodeID)
			if err := next.Start(h.nc, h.getLogCfg(), h.reloadCh); err != nil {
				log.WithField("err", err).Errorf("节点 #%d 独立重载失败，将在下次拉取重试", h.nodeID)
				_ = next.Close()
				h.active.Store(false)
				return
			}
			h.rt = next
			runtime.GC()
			log.Infof("节点 #%d 独立重载完成", h.nodeID)
		}
	}
}

func (h *nodeHandle) stop() {
	close(h.stopCh)
	<-h.doneCh
	h.active.Store(false)
	if h.rt != nil {
		if err := h.rt.Close(); err != nil {
			log.WithField("err", err).Errorf("关闭节点 #%d 失败", h.nodeID)
		}
		h.rt = nil
	}
}

// machineRunner 节点机模式：按面板下发配置为每个节点维护独立生命周期，互不影响；凭据被吊销时停止全部节点。
type machineRunner struct {
	client     *machine.Client
	newRuntime func(nodeID int) nodeRuntime
	handles    map[int]*nodeHandle
	cfg        *machine.Config
	fails      int
	// triedUpdate 已尝试过的更新指令，同一指令只尝试一次。
	triedUpdate int64
}

func (r *machineRunner) running() bool {
	for _, h := range r.handles {
		if h.alive() {
			return true
		}
	}
	return false
}

func (r *machineRunner) stopAll() {
	if len(r.handles) == 0 {
		return
	}
	for id, h := range r.handles {
		h.stop()
		delete(r.handles, id)
	}
	runtime.GC()
}

// reconcile 按最新配置增量增删并重试未就绪节点；对已在运行且配置未变的节点完全不中断。
func (r *machineRunner) reconcile(cfg *machine.Config) {
	c := cfg.Conf(r.client.Cred)
	if r.cfg == nil || r.cfg.LogLevel != cfg.LogLevel {
		setLogLevel(c.LogConfig.Level)
	}
	firstSync := r.cfg == nil
	r.cfg = cfg

	if r.handles == nil {
		r.handles = make(map[int]*nodeHandle)
	}

	wanted := make(map[int]conf.NodeConfig, len(c.NodeConfigs))
	for _, nc := range c.NodeConfigs {
		wanted[nc.NodeID] = nc
	}

	stoppedAny := false
	for id, h := range r.handles {
		if _, ok := wanted[id]; !ok || !h.alive() {
			log.Infof("节点 #%d 已移除或需重建，正在停止...", id)
			h.stop()
			delete(r.handles, id)
			stoppedAny = true
		}
	}
	if stoppedAny {
		runtime.GC()
	}

	if len(c.NodeConfigs) == 0 {
		if firstSync {
			log.Warn("面板没有为这台节点机分配可用节点，等待分配")
		}
		return
	}

	for _, nc := range c.NodeConfigs {
		if h, ok := r.handles[nc.NodeID]; ok {
			h.setLogCfg(c.LogConfig)
			continue
		}
		h, err := startNodeHandle(nc, c.LogConfig, r.newRuntime)
		if err != nil {
			log.WithField("err", err).Errorf("节点 #%d 启动失败，不影响其他节点，将在下次拉取重试", nc.NodeID)
			continue
		}
		r.handles[nc.NodeID] = h
		log.Infof("节点 #%d 已独立启动", nc.NodeID)
	}
}

// poll 拉取一次配置，返回下次拉取的间隔。
func (r *machineRunner) poll() time.Duration {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cfg, changed, err := r.client.Fetch(ctx)
	switch {
	case errors.Is(err, machine.ErrRevoked):
		r.fails++
		if r.fails >= revokeAfter && (r.running() || r.cfg != nil) {
			log.Error("面板拒绝了本机凭据（已吊销或已删除），停止全部节点；重新接入请在面板生成新的安装命令")
			r.stopAll()
			r.cfg = nil
			r.client.Reset()
		} else if r.fails < revokeAfter {
			log.WithField("次数", r.fails).Warn("面板拒绝了本机凭据")
		}
		return r.interval()
	case err != nil:
		log.WithField("err", err).Warn("获取节点机配置失败，保持当前状态")
		return r.interval()
	}
	r.fails = 0
	if cfg != nil {
		if changed {
			log.Info("节点机配置已更新，按节点增量同步")
		}
		r.reconcile(cfg)
		r.update(cfg.Update)
	}
	return r.interval()
}

// update 按面板指令更新程序：下载校验替换后停止节点并原地重启，失败时保留当前程序并上报原因。
func (r *machineRunner) update(u *machine.Update) {
	if u == nil || u.Version == version || u.ID == r.triedUpdate {
		return
	}
	r.triedUpdate = u.ID
	log.Infof("面板要求更新到 %s，开始下载", u.Version)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	exe, err := (&machine.Updater{BaseURL: os.Getenv("V2NODE_RELEASE_BASE")}).Install(ctx, u.Version)
	if err != nil {
		log.WithField("err", err).Error("更新失败，继续运行当前版本")
		r.client.Report(u.ID, err)
		return
	}
	log.Infof("已更新到 %s，重启程序", u.Version)
	r.stopAll()
	err = machine.Restart(exe)
	log.WithField("err", err).Error("重启失败，新版本将在下次启动时生效")
	r.client.Report(u.ID, err)
	if r.cfg != nil {
		r.reconcile(r.cfg)
	}
}

func (r *machineRunner) interval() time.Duration {
	if r.cfg == nil {
		return retryInterval
	}
	d := time.Duration(r.cfg.PullInterval) * time.Second
	if d <= 0 {
		return defaultPull
	}
	return max(d, minPull)
}

func machineHandle(path string) {
	cred, err := machine.Load(path)
	if err != nil {
		log.WithField("err", err).Error("读取节点机凭据失败")
		return
	}
	log.Infof("节点机模式：面板 %s，节点机 #%d，实例 %s", cred.Panel, cred.MachineID, cred.InstanceID)
	limiter.Init()
	host, _ := os.Hostname()
	r := &machineRunner{
		client:     &machine.Client{Cred: cred, Hostname: host, Version: version},
		newRuntime: newXrayRuntime,
	}
	defer r.stopAll()

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)
	timer := time.NewTimer(0)
	for {
		select {
		case <-osSignals:
			log.Info("收到退出信号，正在关闭程序...")
			r.stopAll()
			os.Exit(0)
		case <-timer.C:
			timer.Reset(r.poll())
		}
	}
}
