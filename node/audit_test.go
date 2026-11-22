package node

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/audit"
	"github.com/wyx2685/v2node/conf"
	"github.com/wyx2685/v2node/core"
	"github.com/wyx2685/v2node/limiter"
)

func TestReconcileAuditHotToggleNoReload(t *testing.T) {
	var auditEnable atomic.Bool
	var auditGetCalls atomic.Int64
	var mu sync.Mutex
	var reported []panel.AuditRecord

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/server/config":
			tag := fmt.Sprintf(`"cfg-%t"`, auditEnable.Load())
			if r.Header.Get("If-None-Match") == tag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", tag)
			_, _ = fmt.Fprintf(w,
				`{"protocol":"vless","listen_ip":"0.0.0.0","server_port":8443,"tls":0,"network":"tcp","base_config":{"push_interval":60,"pull_interval":60},"audit_enable":%t}`,
				auditEnable.Load(),
			)
		case "/api/v1/server/UniProxy/audit":
			if r.Method == http.MethodGet {
				auditGetCalls.Add(1)
				w.Header().Set("ETag", `"a1"`)
				if r.Header.Get("If-None-Match") == `"a1"` {
					w.WriteHeader(http.StatusNotModified)
					return
				}
				_, _ = w.Write([]byte(`{"rules":[{"id":1,"action":"block","match":["bad.example"]}]}`))
				return
			}
			var body struct {
				Records []panel.AuditRecord `json:"records"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			reported = append(reported, body.Records...)
			mu.Unlock()
			_, _ = w.Write([]byte(`{"data":true}`))
		case "/api/v1/server/UniProxy/user":
			_, _ = w.Write([]byte(`{"users":[]}`))
		case "/api/v1/server/UniProxy/alivelist":
			_, _ = w.Write([]byte(`{"alive":{}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, err := panel.New(&conf.NodeConfig{APIHost: srv.URL, NodeID: 1, Key: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	info, err := client.GetNodeInfo(ctx)
	if err != nil {
		t.Fatal(err)
	}
	reloadCh := make(chan struct{}, 1)
	c := &Controller{
		apiClient: client,
		info:      info,
		tag:       info.Tag,
		conf:      &conf.NodeConfig{APIHost: srv.URL, NodeID: 1, Key: "tok"},
		limiter:   &limiter.Limiter{},
		server:    &core.V2Core{ReloadCh: reloadCh},
	}
	defer audit.Remove(c.tag)

	// 初始关闭：不注册审计器、不请求 /UniProxy/audit
	c.startAudit()
	if audit.Get(c.tag) != nil || auditGetCalls.Load() != 0 {
		t.Fatalf("初始关闭审计时不应注册或拉取规则: get=%v calls=%d", audit.Get(c.tag), auditGetCalls.Load())
	}

	// 热开启：不触发 ReloadCh，立即拉取并生效规则
	auditEnable.Store(true)
	if err := c.nodeInfoMonitor(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloadCh:
		t.Fatal("仅开启审计不应触发 ReloadCh 重建 Core")
	default:
	}
	a := audit.Get(c.tag)
	if a == nil || !a.Check(10, "1.1.1.1", "tcp", audit.Target{Domain: "sub.bad.example", Port: 443}) {
		t.Fatalf("热开启审计后应立即拦截匹配目标: auditor=%v", a)
	}

	// 热关闭：不触发 ReloadCh，先上报内存中的命中记录再注销审计器
	auditEnable.Store(false)
	if err := c.nodeInfoMonitor(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-reloadCh:
		t.Fatal("仅关闭审计不应触发 ReloadCh 重建 Core")
	default:
	}
	if audit.Get(c.tag) != nil {
		t.Fatal("热关闭审计后应注销审计器")
	}
	mu.Lock()
	gotRep := len(reported)
	mu.Unlock()
	if gotRep != 1 {
		t.Fatalf("热关闭审计前应先上报未刷新记录，实际上报 %d 条", gotRep)
	}

	// 再次热开启同一个未变化的规则：因为关闭时清了 auditEtag，应重新拉到规则而非卡在 304
	auditEnable.Store(true)
	if err := c.nodeInfoMonitor(ctx); err != nil {
		t.Fatal(err)
	}
	a = audit.Get(c.tag)
	if a == nil || !a.Check(10, "1.1.1.1", "tcp", audit.Target{Domain: "sub.bad.example", Port: 443}) {
		t.Fatalf("重新开启审计后应完整拉回规则并生效: auditor=%v", a)
	}
}
