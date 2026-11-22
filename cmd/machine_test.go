package cmd

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/machine"
)

type fakeStats struct {
	mu      sync.Mutex
	starts  map[int]int
	closes  map[int]int
	failIDs map[int]bool
	failOnce map[int]bool
	reload  map[int]chan struct{}
	closed  map[int]chan struct{}
}

func newFakeStats() *fakeStats {
	return &fakeStats{
		starts:   map[int]int{},
		closes:   map[int]int{},
		failIDs:  map[int]bool{},
		failOnce: map[int]bool{},
		reload:   map[int]chan struct{}{},
		closed:   map[int]chan struct{}{},
	}
}

type fakeRuntime struct {
	id    int
	stats *fakeStats
}

func (f *fakeRuntime) Start(_ conf.NodeConfig, _ conf.LogConfig, reloadCh chan struct{}) error {
	f.stats.mu.Lock()
	defer f.stats.mu.Unlock()
	if f.stats.failIDs[f.id] {
		return errors.New("start failed")
	}
	if f.stats.failOnce[f.id] {
		f.stats.failOnce[f.id] = false
		return errors.New("transient fail")
	}
	f.stats.starts[f.id]++
	f.stats.reload[f.id] = reloadCh
	f.stats.closed[f.id] = make(chan struct{})
	return nil
}

func (f *fakeRuntime) Close() error {
	f.stats.mu.Lock()
	ch := f.stats.closed[f.id]
	if ch != nil {
		f.stats.closes[f.id]++
		f.stats.closed[f.id] = nil
	}
	f.stats.mu.Unlock()
	if ch != nil {
		close(ch)
	}
	return nil
}

func (s *fakeStats) count(id int) (starts, closes int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.starts[id], s.closes[id]
}

func (s *fakeStats) waitStarts(t *testing.T, id, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		st, _ := s.count(id)
		if st >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	st, cl := s.count(id)
	t.Fatalf("node %d starts=%d closes=%d, want starts>=%d", id, st, cl, want)
}

func TestMachineRunnerPerNodeIsolation(t *testing.T) {
	var etag atomic.Value
	var nodesMu sync.Mutex
	curLogLevel := "info"
	curNodes := []machine.NodeConfig{{NodeID: 1}, {NodeID: 2}}
	var revoked atomic.Bool
	etag.Store(`"v1"`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/machine/config" || revoked.Load() {
			http.NotFound(w, r)
			return
		}
		tag := etag.Load().(string)
		w.Header().Set("ETag", tag)
		if r.Header.Get("If-None-Match") == tag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		nodesMu.Lock()
		cfg := machine.Config{
			LogLevel:     curLogLevel,
			PullInterval: 60,
			Nodes:        append([]machine.NodeConfig(nil), curNodes...),
		}
		nodesMu.Unlock()
		_ = json.NewEncoder(w).Encode(cfg)
	}))
	defer srv.Close()

	st := newFakeStats()
	st.failIDs[4] = true

	runner := &machineRunner{
		client: &machine.Client{
			Cred:    &machine.Credential{Panel: srv.URL, MachineID: 1, Token: "gvm_test"},
			Version: "v0.5.4",
		},
		newRuntime: func(id int) nodeRuntime { return &fakeRuntime{id: id, stats: st} },
	}
	defer runner.stopAll()

	// 1. 首次拉取启动节点 1 和 2
	runner.poll()
	if s1, c1 := st.count(1); s1 != 1 || c1 != 0 {
		t.Fatalf("node 1 应启动 1 次且未关闭: %d/%d", s1, c1)
	}
	if s2, c2 := st.count(2); s2 != 1 || c2 != 0 {
		t.Fatalf("node 2 应启动 1 次且未关闭: %d/%d", s2, c2)
	}

	// 2. 增量移除节点 2、新增节点 3 与会失败的节点 4：节点 1 全程不关闭、不重启
	nodesMu.Lock()
	curNodes = []machine.NodeConfig{{NodeID: 1}, {NodeID: 3}, {NodeID: 4}}
	curLogLevel = "debug"
	nodesMu.Unlock()
	etag.Store(`"v2"`)

	runner.poll()
	if s1, c1 := st.count(1); s1 != 1 || c1 != 0 {
		t.Fatalf("增删兄弟节点后 node 1 不应被重启或关闭: %d/%d", s1, c1)
	}
	if s2, c2 := st.count(2); s2 != 1 || c2 != 1 {
		t.Fatalf("移除的 node 2 应已关闭: %d/%d", s2, c2)
	}
	if s3, c3 := st.count(3); s3 != 1 || c3 != 0 {
		t.Fatalf("新增的 node 3 应已启动: %d/%d", s3, c3)
	}
	if s4, _ := st.count(4); s4 != 0 || runner.handles[4] != nil {
		t.Fatalf("失败的 node 4 不应留存句柄")
	}

	// 3. node 4 恢复可用，即使面板返回 304 Not Modified，下次 poll 仍重试并拉起 node 4，且不影响 node 1 / 3
	st.mu.Lock()
	st.failIDs[4] = false
	st.mu.Unlock()
	runner.poll()
	if s4, c4 := st.count(4); s4 != 1 || c4 != 0 {
		t.Fatalf("304 轮询应自动重试并拉起 node 4: %d/%d", s4, c4)
	}
	if s1, c1 := st.count(1); s1 != 1 || c1 != 0 {
		t.Fatalf("重试 node 4 不应影响 node 1: %d/%d", s1, c1)
	}

	// 4. 触发节点 3 的 reloadCh：只有节点 3 重启，节点 1 与 4 全程零重启
	st.mu.Lock()
	rch3 := st.reload[3]
	st.mu.Unlock()
	rch3 <- struct{}{}
	st.waitStarts(t, 3, 2)
	if _, c3 := st.count(3); c3 != 1 {
		t.Fatalf("node 3 reload 后应关闭旧实例 1 次，实际 %d", c3)
	}
	if s1, c1 := st.count(1); s1 != 1 || c1 != 0 {
		t.Fatalf("node 3 reload 不应影响 node 1: %d/%d", s1, c1)
	}
	if s4, c4 := st.count(4); s4 != 1 || c4 != 0 {
		t.Fatalf("node 3 reload 不应影响 node 4: %d/%d", s4, c4)
	}

	// 5. 节点 3 reload 期间短暂失败，句柄标记失活；下次 poll 清理并重建，仍不影响节点 1
	st.mu.Lock()
	st.failOnce[3] = true
	rch3 = st.reload[3]
	st.mu.Unlock()
	rch3 <- struct{}{}
	deadline := time.Now().Add(2 * time.Second)
	for runner.handles[3].alive() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if runner.handles[3].alive() {
		t.Fatal("reload 失败后 node 3 应标记为非活跃")
	}
	runner.poll()
	st.waitStarts(t, 3, 3)
	if s1, c1 := st.count(1); s1 != 1 || c1 != 0 {
		t.Fatalf("重建失败的 node 3 不应影响 node 1: %d/%d", s1, c1)
	}

	// 6. 连续 3 次 404 吊销全部节点
	revoked.Store(true)
	runner.poll()
	if !runner.running() {
		t.Fatal("第 1 次 404 不应立刻停服")
	}
	runner.poll()
	runner.poll()
	if runner.running() {
		t.Fatal("连续 3 次 404 后应停止全部节点")
	}
	if _, c1 := st.count(1); c1 != 1 {
		t.Fatalf("吊销后 node 1 应已关闭，实际 %d", c1)
	}
}
