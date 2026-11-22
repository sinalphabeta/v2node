package machine

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVerifyFetch(t *testing.T) {
	revoked := false
	var seenInst, seenHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/server/machine/config":
			q := r.URL.Query()
			if revoked || r.Header.Get("Authorization") != "Bearer gvm_abc" || q.Get("version") != "v1" || q.Get("instance_id") == "" {
				http.NotFound(w, r)
				return
			}
			seenInst = q.Get("instance_id")
			seenHost = q.Get("hostname")
			w.Header().Set("ETag", `"e1"`)
			if r.Header.Get("If-None-Match") == `"e1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = w.Write([]byte(`{"machine_id":7,"log_level":"debug","pull_interval":30,"nodes":[{"node_id":1},{"node_id":2}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ctx := context.Background()

	if _, err := Verify(ctx, srv.URL, "gvm_bad", "", "h", "v1"); err == nil {
		t.Fatal("错误 Token 应失败")
	}
	if _, err := Verify(ctx, "ftp://x", "gvm_abc", "", "h", "v1"); err == nil {
		t.Fatal("非 http 地址应失败")
	}
	cred, err := Verify(ctx, srv.URL+"/", "gvm_abc", "", "vps-h", "v1")
	if err != nil || cred.Panel != srv.URL || cred.MachineID != 7 || cred.Token != "gvm_abc" || cred.InstanceID == "" {
		t.Fatalf("校验接入结果不符: %+v %v", cred, err)
	}
	if seenInst != cred.InstanceID || seenHost != "vps-h" {
		t.Fatalf("未携带 instance_id 或 hostname: inst=%q host=%q", seenInst, seenHost)
	}
	// 传入已有 instanceID 时应原样保留
	cred2, err := Verify(ctx, srv.URL, "gvm_abc", "keep-id", "vps-h", "v1")
	if err != nil || cred2.InstanceID != "keep-id" {
		t.Fatalf("应保留已有 instance_id: %+v %v", cred2, err)
	}

	path := filepath.Join(t.TempDir(), "sub", "machine.json")
	if err := Save(path, cred); err != nil {
		t.Fatal(err)
	}
	if st, err := os.Stat(path); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Fatalf("凭据文件权限不符: %v %v", st, err)
	}
	loaded, err := Load(path)
	if err != nil || *loaded != *cred {
		t.Fatalf("读取凭据不符: %+v %v", loaded, err)
	}
	// 缺少 instance_id 的旧凭据文件在 Load 时应自动补全并写回
	legacyPath := filepath.Join(t.TempDir(), "legacy.json")
	if err := os.WriteFile(legacyPath, []byte(`{"panel":"http://127.0.0.1","machine_id":7,"token":"gvm_abc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	healed, err := Load(legacyPath)
	if err != nil || healed.InstanceID == "" {
		t.Fatalf("旧凭据应自动补全 instance_id: %+v %v", healed, err)
	}
	healedReload, err := Load(legacyPath)
	if err != nil || healedReload.InstanceID != healed.InstanceID {
		t.Fatalf("自动补全的 instance_id 应已持久化: %+v vs %+v", healedReload, healed)
	}

	c := &Client{Cred: loaded, Hostname: "vps-h", Version: "v1"}
	cfg, changed, err := c.Fetch(ctx)
	if err != nil || !changed || cfg.MachineID != 7 || cfg.PullInterval != 30 || len(cfg.Nodes) != 2 {
		t.Fatalf("首次拉取不符: %+v %v %v", cfg, changed, err)
	}
	cc := cfg.Conf(loaded)
	if cc.LogConfig.Level != "debug" || len(cc.NodeConfigs) != 2 || cc.NodeConfigs[1].NodeID != 2 ||
		cc.NodeConfigs[0].APIHost != srv.URL || cc.NodeConfigs[0].Key != "gvm_abc" {
		t.Fatalf("转换配置不符: %+v", cc)
	}
	if again, changed, err := c.Fetch(ctx); err != nil || changed || again != cfg {
		t.Fatalf("ETag 未生效: %v %v", changed, err)
	}
	c.Reset()
	if _, changed, _ := c.Fetch(ctx); !changed {
		t.Fatal("Reset 后应返回完整配置")
	}
	revoked = true
	if _, _, err := c.Fetch(ctx); !errors.Is(err, ErrRevoked) {
		t.Fatalf("吊销后应返回 ErrRevoked: %v", err)
	}
}
