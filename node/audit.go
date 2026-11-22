package node

import (
	"context"
	"errors"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/wyx2685/v2node/common/audit"
)

// syncAuditRules 从面板拉取审计规则，有变化时替换。
func (c *Controller) syncAuditRules(ctx context.Context) error {
	rules, changed, err := c.apiClient.GetAuditRules(ctx)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Error("Get audit rules failed")
		return nil
	}
	if changed {
		c.auditor.SetRules(rules)
	}
	return nil
}

// reportAudit 上报审计命中记录，失败时放回等待下次上报。
func (c *Controller) reportAudit(ctx context.Context) error {
	records := c.auditor.Flush()
	if len(records) == 0 {
		return nil
	}
	if err := c.apiClient.ReportAudit(ctx, records); err != nil {
		c.auditor.Restore(records)
		log.WithFields(log.Fields{"tag": c.tag, "err": err}).Info("Report audit records failed")
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return nil
	}
	log.WithField("tag", c.tag).Infof("Report %d audit records", len(records))
	return nil
}

// startAudit 节点开启审计时注册审计器并拉取一次规则。
func (c *Controller) startAudit() {
	enabled := c.info != nil && c.info.Common != nil && c.info.Common.AuditEnable
	if !enabled && c.apiClient != nil {
		enabled = c.apiClient.AuditEnabled()
	}
	if !enabled {
		return
	}
	c.auditor = audit.Register(c.tag)
	_ = c.syncAuditRules(context.Background())
}

// reconcileAudit 按面板最新下发的 audit_enable 热启停审计器，不重建 Xray Core。
// 若本轮刚开启审计并已完成规则拉取，返回 true。
func (c *Controller) reconcileAudit(ctx context.Context) bool {
	if c.apiClient == nil {
		return false
	}
	want := c.apiClient.AuditEnabled()
	if c.info != nil && c.info.Common != nil {
		c.info.Common.AuditEnable = want
	}
	if want && c.auditor == nil {
		c.auditor = audit.Register(c.tag)
		_ = c.syncAuditRules(ctx)
		log.WithField("tag", c.tag).Info("Audit enabled by panel")
		return true
	}
	if !want && c.auditor != nil {
		c.closeAudit()
		log.WithField("tag", c.tag).Info("Audit disabled by panel")
	}
	return false
}

// closeAudit 尽量上报剩余的审计记录后注销审计器，并重置规则 ETag 以便下次重开时重新拉取。
func (c *Controller) closeAudit() {
	if c.auditor == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = c.reportAudit(ctx)
	audit.Remove(c.tag)
	c.auditor = nil
	if c.apiClient != nil {
		c.apiClient.ResetAuditETag()
	}
}
