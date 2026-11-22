package core

import (
	"testing"

	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/conf"
)

func TestStartReturnsErrorOnInvalidCustomConfig(t *testing.T) {
	badDNS := ":::"
	v2 := New(conf.New())
	infos := []*panel.NodeInfo{
		{
			Id:   1,
			Type: "vless",
			Tag:  "test-invalid",
			Common: &panel.CommonNode{
				Routes: []panel.Route{
					{
						Id:          1,
						Action:      "dns",
						Match:       []string{"geosite:cn"},
						ActionValue: &badDNS,
					},
				},
			},
		},
	}

	// 验证无效路由规则导致 GetCustomConfig/Build 或 core.New 失败时返回 error，而不是 log.Panic 拖垮整机。
	err := v2.Start(infos)
	if err == nil {
		_ = v2.Close()
		t.Fatal("expected Start to return error on invalid custom config")
	}
}
