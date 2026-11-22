package cmd

import (
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/limiter"
	"github.com/wyx2685/v2node/machine"
)

var (
	config      string
	watch       bool
	machineFile string
)

var serverCommand = cobra.Command{
	Use:   "server",
	Short: "Run v2node server",
	Run:   serverHandle,
	Args:  cobra.NoArgs,
}

func init() {
	serverCommand.PersistentFlags().
		StringVarP(&config, "config", "c",
			"/etc/v2node/config.json", "config file path")
	serverCommand.PersistentFlags().
		BoolVarP(&watch, "watch", "w",
			true, "watch file path change")
	serverCommand.PersistentFlags().
		StringVar(&machineFile, "machine", machine.DefaultPath,
			"节点机凭据文件，存在时进入节点机模式（配置由面板下发，忽略 --config）")
	command.AddCommand(&serverCommand)
}

func serverHandle(_ *cobra.Command, _ []string) {
	showVersion()
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: true,
		DisableQuote:     true,
		PadLevelText:     false,
	})
	if _, err := os.Stat(machineFile); err == nil {
		machineHandle(machineFile)
		return
	}
	c := conf.New()
	err := c.LoadFromPath(config)
	if err != nil {
		log.WithField("err", err).Error("Load config file failed")
		return
	}
	// Enable pprof if configured
	if c.PprofPort != 0 {
		go func() {
			log.Infof("Starting pprof server on :%d", c.PprofPort)
			if err := http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", c.PprofPort), nil); err != nil {
				log.WithField("err", err).Error("pprof server failed")
			}
		}()
	}
	limiter.Init()

	runner := &configRunner{newRuntime: newXrayRuntime}
	runner.applyConf(c)
	defer runner.stopAll()
	log.Info("Nodes started")

	var reloadCh = make(chan struct{}, 1)
	if watch {
		err = conf.WatchFile(config, func() {
			select {
			case reloadCh <- struct{}{}:
			default:
			}
		})
		if err != nil {
			log.WithField("err", err).Error("start watch failed")
			return
		}
	}
	runtime.GC()

	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-osSignals:
			log.Info("收到退出信号，正在关闭程序...")
			runner.stopAll()
			os.Exit(0)
		case <-reloadCh:
			log.Info("收到配置文件变更信号，正在增量重载...")
			runner.reloadFromPath(config)
		case <-ticker.C:
			runner.reconcile()
		}
	}
}

type configKey struct {
	host   string
	nodeID int
}

// configRunner 传统 config.json 模式：同样按节点隔离 V2Core 与 Controller，避免单节点异常或证书更新拖垮整机。
type configRunner struct {
	newRuntime func(nodeID int) nodeRuntime
	handles    map[configKey]*nodeHandle
	desired    []conf.NodeConfig
	logCfg     conf.LogConfig
	hasLog     bool
}

func keyOf(nc conf.NodeConfig) configKey {
	return configKey{host: nc.APIHost, nodeID: nc.NodeID}
}

func effectiveRetryCount(nc conf.NodeConfig) int {
	if nc.RetryCount == nil {
		return conf.DefaultNodeRetryCount
	}
	return *nc.RetryCount
}

func nodeConfigEqual(a, b conf.NodeConfig) bool {
	return a.APIHost == b.APIHost &&
		a.NodeID == b.NodeID &&
		a.Key == b.Key &&
		a.Timeout == b.Timeout &&
		effectiveRetryCount(a) == effectiveRetryCount(b)
}

func applyLogConfig(cur *conf.LogConfig, next conf.LogConfig, initialized bool) {
	setLogLevel(next.Level)
	if initialized && cur.Output == next.Output {
		*cur = next
		return
	}
	oldWriter, wasFile := log.StandardLogger().Out.(*os.File)
	if next.Output != "" {
		f, err := os.OpenFile(next.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.WithField("err", err).Error("Open log file failed, using stdout instead")
		} else {
			log.SetOutput(f)
			if wasFile && oldWriter != os.Stdout && oldWriter != os.Stderr {
				_ = oldWriter.Close()
			}
		}
	} else if initialized && cur.Output != "" {
		log.SetOutput(os.Stdout)
		if wasFile && oldWriter != os.Stdout && oldWriter != os.Stderr {
			_ = oldWriter.Close()
		}
	}
	*cur = next
}

func (r *configRunner) stopAll() {
	if len(r.handles) == 0 {
		return
	}
	for k, h := range r.handles {
		h.stop()
		delete(r.handles, k)
	}
	runtime.GC()
}

func (r *configRunner) applyConf(c *conf.Conf) {
	if r.handles == nil {
		r.handles = make(map[configKey]*nodeHandle)
	}
	applyLogConfig(&r.logCfg, c.LogConfig, r.hasLog)
	r.hasLog = true

	wanted := make(map[configKey]conf.NodeConfig, len(c.NodeConfigs))
	desired := make([]conf.NodeConfig, 0, len(c.NodeConfigs))
	for _, nc := range c.NodeConfigs {
		k := keyOf(nc)
		if _, dup := wanted[k]; dup {
			continue
		}
		wanted[k] = nc
		desired = append(desired, nc)
	}
	r.desired = desired

	stoppedAny := false
	for k, h := range r.handles {
		nc, ok := wanted[k]
		if !ok || !h.alive() || !nodeConfigEqual(h.nc, nc) {
			log.Infof("节点 #%d (%s) 已移除、配置变更或失活，正在停止...", k.nodeID, k.host)
			h.stop()
			delete(r.handles, k)
			stoppedAny = true
		} else {
			h.setLogCfg(r.logCfg)
		}
	}
	if stoppedAny {
		runtime.GC()
	}

	r.startMissing()
}

func (r *configRunner) reconcile() {
	if r.handles == nil {
		return
	}
	stoppedAny := false
	for k, h := range r.handles {
		if !h.alive() {
			log.Infof("节点 #%d (%s) 已失活，准备重建...", k.nodeID, k.host)
			h.stop()
			delete(r.handles, k)
			stoppedAny = true
		}
	}
	if stoppedAny {
		runtime.GC()
	}
	r.startMissing()
}

func (r *configRunner) startMissing() {
	for _, nc := range r.desired {
		k := keyOf(nc)
		if h, ok := r.handles[k]; ok && h.alive() {
			continue
		}
		h, err := startNodeHandle(nc, r.logCfg, r.newRuntime)
		if err != nil {
			log.WithField("err", err).Errorf("节点 #%d (%s) 启动失败，不影响其他节点，将在 %s 后重试", nc.NodeID, nc.APIHost, retryInterval)
			continue
		}
		r.handles[k] = h
		log.Infof("节点 #%d (%s) 已独立启动", nc.NodeID, nc.APIHost)
	}
}

func (r *configRunner) reloadFromPath(path string) {
	next := conf.New()
	if err := next.LoadFromPath(path); err != nil {
		log.WithField("err", err).Error("重新加载配置文件失败，保持当前节点运行状态")
		return
	}
	r.applyConf(next)
	log.Info("配置文件增量重载完成")
}
