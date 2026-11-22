package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyx2685/v2node/conf"
)

func TestConfigRunnerPerNodeIsolation(t *testing.T) {
	st := newFakeStats()
	// 节点 4（如某 TLS 节点证书失败）持续启动失败，不能影响节点 1 与节点 2
	st.failIDs[4] = true

	runner := &configRunner{
		newRuntime: func(id int) nodeRuntime { return &fakeRuntime{id: id, stats: st} },
	}
	defer runner.stopAll()

	// 1. 首次加载：节点 1、2、4 同在 config.json，节点 4 失败时节点 1、2 应正常启动
	runner.applyConf(&conf.Conf{
		LogConfig: conf.LogConfig{Level: "info"},
		NodeConfigs: []conf.NodeConfig{
			{APIHost: "https://panel-a.test", NodeID: 1, Key: "k1"},
			{APIHost: "https://panel-a.test", NodeID: 2, Key: "k2"},
			{APIHost: "https://panel-a.test", NodeID: 4, Key: "k4"},
		},
	})
	if s1, c1 := st.count(1); s1 != 1 || c1 != 0 {
		t.Fatalf("node 1 应启动 1 次且未关闭: %d/%d", s1, c1)
	}
	if s2, c2 := st.count(2); s2 != 1 || c2 != 0 {
		t.Fatalf("node 2 应启动 1 次且未关闭: %d/%d", s2, c2)
	}
	if s4, _ := st.count(4); s4 != 0 || runner.handles[configKey{host: "https://panel-a.test", nodeID: 4}] != nil {
		t.Fatalf("失败的 node 4 不应阻断兄弟节点，也不应留存句柄")
	}

	// 2. 节点 4 恢复可用，reconcile 自动重试拉起，且不干扰节点 1、2
	st.mu.Lock()
	st.failIDs[4] = false
	st.mu.Unlock()
	runner.reconcile()
	if s4, c4 := st.count(4); s4 != 1 || c4 != 0 {
		t.Fatalf("reconcile 应自动重试拉起 node 4: %d/%d", s4, c4)
	}
	if s1, c1 := st.count(1); s1 != 1 || c1 != 0 {
		t.Fatalf("重试 node 4 不应影响 node 1: %d/%d", s1, c1)
	}

	// 3. 触发节点 2 的独立 reloadCh（例如面板推送更新证书），且在 reload 期间失败：
	//    节点 1、4 全程不断流；节点 2 失活并在下次 reconcile 自动拉起
	st.mu.Lock()
	st.failOnce[2] = true
	rch2 := st.reload[2]
	st.mu.Unlock()
	rch2 <- struct{}{}
	k2 := configKey{host: "https://panel-a.test", nodeID: 2}
	deadline := time.Now().Add(2 * time.Second)
	for runner.handles[k2].alive() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if runner.handles[k2].alive() {
		t.Fatal("reload 失败后 node 2 应标记为非活跃")
	}
	if s1, c1 := st.count(1); s1 != 1 || c1 != 0 {
		t.Fatalf("node 2 reload 失败不应影响 node 1: %d/%d", s1, c1)
	}
	if s4, c4 := st.count(4); s4 != 1 || c4 != 0 {
		t.Fatalf("node 2 reload 失败不应影响 node 4: %d/%d", s4, c4)
	}

	runner.reconcile()
	st.waitStarts(t, 2, 2)
	if s1, c1 := st.count(1); s1 != 1 || c1 != 0 {
		t.Fatalf("重建 node 2 不应影响 node 1: %d/%d", s1, c1)
	}

	// 4. 磁盘 config.json 增量重载：删节点 4、改节点 2 ApiKey、新增跨面板同 ID 节点 1 (panel-b)，节点 1 (panel-a) 不重启；
	//    写坏 config.json 时应保留所有正在运行的节点
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	writeCfg := func(nodes []conf.NodeConfig) {
		t.Helper()
		rawNodes := make([]map[string]any, 0, len(nodes))
		for _, nc := range nodes {
			rawNodes = append(rawNodes, map[string]any{
				"ApiHost": nc.APIHost,
				"NodeID":  nc.NodeID,
				"ApiKey":  nc.Key,
			})
		}
		b, err := json.Marshal(map[string]any{
			"Log":   map[string]any{"Level": "debug", "Access": "none"},
			"Nodes": rawNodes,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfgPath, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeCfg([]conf.NodeConfig{
		{APIHost: "https://panel-a.test", NodeID: 1, Key: "k1"},
		{APIHost: "https://panel-a.test", NodeID: 2, Key: "k2-new"},
		{APIHost: "https://panel-b.test", NodeID: 1, Key: "kb1"},
	})
	// 先将 panel-b 的 key 与 panel-a 区分（fakeStats 按 int ID 计数，这里重点验证未改动的 node 1 panel-a 不被关闭）
	runner.reloadFromPath(cfgPath)
	if _, c4 := st.count(4); c4 != 1 {
		t.Fatalf("移除的 node 4 应被关闭 1 次，实际 %d", c4)
	}
	if s2, c2 := st.count(2); s2 != 3 || c2 != 2 {
		t.Fatalf("ApiKey 变更的 node 2 应重启一次 (starts=3/closes=2)，实际 %d/%d", s2, c2)
	}
	if _, c1 := st.count(1); c1 != 0 {
		t.Fatalf("未变更的 panel-a node 1 不应被关闭，实际 closes=%d", c1)
	}
	if _, ok := runner.handles[configKey{host: "https://panel-b.test", nodeID: 1}]; !ok {
		t.Fatal("跨面板同 NodeID 的节点应使用 (APIHost, NodeID) 独立运行")
	}

	// 写坏配置文件时不断流
	if err := os.WriteFile(cfgPath, []byte("{bad-json"), 0600); err != nil {
		t.Fatal(err)
	}
	runner.reloadFromPath(cfgPath)
	if len(runner.handles) != 3 {
		t.Fatalf("损坏的配置不应停止已运行节点，期望 3 个句柄，实际 %d", len(runner.handles))
	}
}
