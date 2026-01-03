#!/bin/bash

red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
plain='\033[0m'

# 1. 检查并创建 data 目录
if [[ ! -d "./data" ]]; then
    echo -e "${green}检测到 data 目录不存在，正在创建...${plain}"
    mkdir -p ./data
else
    echo -e "${green}data 目录已存在。${plain}"
fi

# 2. 下载或更新 GeoIP 和 GeoSite 数据库
download_dat() {
    local file=$1
    local url="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/${file}"
    local filepath="./data/${file}"
    
    if [[ -f "$filepath" ]]; then
         echo -e "${yellow}检测到 ${file} 已存在，正在更新...${plain}"
    else
         echo -e "${green}未检测到 ${file}，正在下载...${plain}"
    fi

    # 使用 curl 下载，跟进重定向 (-L)，显示进度条
    curl -L "${url}" -o "$filepath"
    
    if [[ $? -ne 0 ]]; then
        echo -e "${red}下载 ${file} 失败，请检查网络连接！${plain}"
    else
        echo -e "${green}${file} 处理完成！${plain}"
    fi
}

download_dat "geoip.dat"
download_dat "geosite.dat"

# 3. 检查 config1.json，不存在则创建
if [[ -f "./config1.json" ]]; then
    echo -e "${yellow}检测到 config1.json 已存在，跳过生成步骤（保留现有配置）。${plain}"
else
    echo -e "${green}config1.json 不存在，正在生成默认模板...${plain}"
    cat > ./config1.json <<EOF
{
  "Log": {
    "Level": "info",
    "Output": "",
    "Access": "none"
  },
  "Nodes": [
    {
      "ApiHost": "https://your-v2board-domain.com",
      "NodeID": 1,
      "ApiKey": "你的通讯密钥",
      "Timeout": 30
    }
  ]
}
EOF
    echo -e "${green}config1.json 生成成功。请记得修改文件填入正确的 Key 和 Host。${plain}"
fi

# 4. 检查 docker-compose.yml，不存在则创建
if [[ -f "./docker-compose.yml" ]]; then
    echo -e "${yellow}检测到 docker-compose.yml 已存在，跳过生成步骤。${plain}"
else
    echo -e "${green}docker-compose.yml 不存在，正在生成...${plain}"
    cat > ./docker-compose.yml <<EOF
name: v2node
services:
  node-1:
    image: ghcr.io/wyx2685/v2node:latest
    restart: always
    network_mode: host
    volumes:
      - ./data/geosite.dat:/usr/local/bin/geosite.dat
      - ./data/geoip.dat:/usr/local/bin/geoip.dat
      - ./config1.json:/etc/v2node/config.json
    environment:
      - TZ=Asia/Shanghai
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
EOF
    echo -e "${green}docker-compose.yml 生成成功。${plain}"
fi

echo -e "${green}所有脚本任务执行完毕。${plain}"
