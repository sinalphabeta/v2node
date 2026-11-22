# v2node
A v2board backend base on moddified xray-core.
一个基于修改版xray内核的V2board节点服务端。

**注意： 本项目需要搭配[修改版V2board](https://github.com/wyx2685/v2board)**

## 软件安装

### 一键安装

```
wget -N https://raw.githubusercontent.com/sinalphabeta/v2node/main/script/install.sh && bash install.sh
```

### 节点机模式（配合 V2go / Gvboard 面板一次性接入）

在面板系统配置「节点」中开启「节点机一次性接入」后，可在「节点机」页面添加服务器并生成一次性安装命令：

```
wget -N https://raw.githubusercontent.com/sinalphabeta/v2node/main/script/install.sh && bash install.sh --panel https://面板地址 --code 接入码
```

已安装 v2node 的服务器也可以直接执行：

```
v2node enroll --panel https://面板地址 --code 接入码 && systemctl restart v2node
```

- 接入后本机专属凭据保存在 `/etc/v2node/machine.json`（仅 root 可读），`v2node server` 会自动以节点机模式运行，由面板下发节点、审计开关与日志级别，并支持面板远程更新。
- 删除 `/etc/v2node/machine.json` 并重启即可切回传统 `config.json` 模式。

### Docker-Compose 安装

```
wget -N https://raw.githubusercontent.com/sinalphabeta/v2node/master/script/docker-compose-install.sh && bash docker-compose-install.sh
```

## 审计

搭配支持的面板（Gvboard / V2go）时，可以在节点配置中开启审计：

```json
{
    "Nodes": [
        {
            "ApiHost": "https://panel.example.com",
            "NodeID": 1,
            "ApiKey": "节点通信密钥",
            "AuditEnable": true
        }
    ]
}
```

- `AuditEnable` 默认关闭，关闭时与常规版本完全相同，不请求审计接口。
- 开启后随节点信息一起从面板拉取审计规则（`/api/v1/server/UniProxy/audit`），随流量一起上报命中记录。
- 规则动作：记录（放行并上报）、阻断（断开连接并上报）、封禁用户（断开连接，本节点 10 分钟内拒绝该用户的所有连接，面板收到上报后封禁整个账号）。
- 节点不做 DNS 解析：域名规则只匹配客户端请求或嗅探到的域名，IP 规则只匹配直接以 IP 访问的连接。
- 面板不支持审计接口（返回 404）时视为没有规则。

## 构建
``` bash
GOEXPERIMENT=jsonv2 go build -v -o build_assets/v2node -trimpath -ldflags "-X 'github.com/sinalphabeta/v2node/cmd.version=$version' -s -w -buildid="
```

## Stars 增长记录

[![Stargazers over time](https://starchart.cc/sinalphabeta/v2node.svg?variant=adaptive)](https://starchart.cc/sinalphabeta/v2node)
