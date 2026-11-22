package panel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/wyx2685/v2node/conf"
)

func TestGetNodeInfoAuditHotToggle(t *testing.T) {
	var auditEnable atomic.Bool
	var serverPort atomic.Int64
	serverPort.Store(8443)
	var etagSeq atomic.Int64

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/server/config" {
			http.NotFound(w, r)
			return
		}
		tag := fmt.Sprintf(`"e-%d-%v-%d"`, serverPort.Load(), auditEnable.Load(), etagSeq.Load())
		if r.Header.Get("If-None-Match") == tag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", tag)
		_, _ = fmt.Fprintf(w,
			`{"protocol":"vless","listen_ip":"0.0.0.0","server_port":%d,"tls":0,"network":"tcp","base_config":{"push_interval":60,"pull_interval":60},"audit_enable":%t}`,
			serverPort.Load(), auditEnable.Load(),
		)
	}))
	defer srv.Close()

	c, err := New(&conf.NodeConfig{APIHost: srv.URL, NodeID: 1, Key: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	// 首次拉取：audit_enable=false
	info, err := c.GetNodeInfo(ctx)
	if err != nil || info == nil || info.Common.AuditEnable || c.AuditEnabled() {
		t.Fatalf("首次拉取结果不符: info=%+v audit=%v err=%v", info, c.AuditEnabled(), err)
	}

	// 未变化：304 返回 nil
	if info, err := c.GetNodeInfo(ctx); err != nil || info != nil {
		t.Fatalf("未变化时应返回 nil: %+v %v", info, err)
	}

	// 仅 audit_enable 变为 true：不返回 NodeInfo（不触发 ReloadCh），但 AuditEnabled 变为 true
	auditEnable.Store(true)
	if info, err := c.GetNodeInfo(ctx); err != nil || info != nil || !c.AuditEnabled() {
		t.Fatalf("仅开启审计不应触发重载: info=%+v audit=%v err=%v", info, c.AuditEnabled(), err)
	}

	// 仅 audit_enable 变为 false：同样不触发重载，AuditEnabled 变为 false
	auditEnable.Store(false)
	if info, err := c.GetNodeInfo(ctx); err != nil || info != nil || c.AuditEnabled() {
		t.Fatalf("仅关闭审计不应触发重载: info=%+v audit=%v err=%v", info, c.AuditEnabled(), err)
	}

	// 端口等核心配置变化：必须返回 NodeInfo 触发重载，并同步新的 AuditEnable
	auditEnable.Store(true)
	serverPort.Store(9443)
	info, err = c.GetNodeInfo(ctx)
	if err != nil || info == nil || info.Common.ServerPort != 9443 || !info.Common.AuditEnable || !c.AuditEnabled() {
		t.Fatalf("核心配置变化应触发重载: info=%+v audit=%v err=%v", info, c.AuditEnabled(), err)
	}
}
