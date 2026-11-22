package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/wyx2685/v2node/machine"
)

var (
	enrollPanel string
	enrollToken string
	enrollFile  string
)

var enrollCommand = cobra.Command{
	Use:   "enroll",
	Short: "使用面板固定 Token 接入面板（节点机模式）",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		if enrollPanel == "" || enrollToken == "" {
			return fmt.Errorf("必须提供 --panel 与 --token")
		}
		var instanceID string
		if old, err := machine.Load(enrollFile); err == nil && old.InstanceID != "" {
			instanceID = old.InstanceID
		}
		host, _ := os.Hostname()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cred, err := machine.Verify(ctx, enrollPanel, enrollToken, instanceID, host, version)
		if err != nil {
			return err
		}
		if err := machine.Save(enrollFile, cred); err != nil {
			return fmt.Errorf("保存凭据失败: %w", err)
		}
		fmt.Printf("接入成功（节点机 #%d，实例 %s），凭据已保存到 %s，重启 v2node 后生效\n", cred.MachineID, cred.InstanceID, enrollFile)
		return nil
	},
}

func init() {
	enrollCommand.Flags().StringVar(&enrollPanel, "panel", "", "面板地址，如 https://panel.example.com")
	enrollCommand.Flags().StringVar(&enrollToken, "token", "", "面板中节点机的固定接入 Token")
	enrollCommand.Flags().StringVar(&enrollFile, "file", machine.DefaultPath, "凭据保存位置")
	command.AddCommand(&enrollCommand)
}
