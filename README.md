# XSSCAN

> Exposure Surface Scan — 面向公网入口的暴露面扫描工具

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 📖 简介

**XSSCAN** 是一款面向安全工程师和运维人员的**暴露面扫描工具**，专注于发现公网业务入口中常见中间件的**错误配置与未授权访问风险**。

在企业上云、敏捷开发的背景下，大量中间件（如 Nacos、XXL-Job、Spring Boot Admin 等）被默认部署并直接暴露在公网，而其中不少存在未鉴权、弱密码或敏感接口开放的问题。XSSCAN 正是为了解决这一痛点而设计——帮助用户在攻击者之前**先发现"灯下黑"的暴露资产**。

## 🎯 核心能力

- **中间件识别与扫描** — 自动识别目标公网入口的中间件类型
- **多目标支持** — 支持单个 URL、URL 列表文件的批量扫描
- **可扩展架构** — 插件式扫描模块，用户可快速新增中间件检测规则
- **结果导出** — 支持 JSON / HTML / CSV 多格式报告输出

## 🛠️ 支持扫描的中间件（部分）

| 中间件 | 默认端口 | 检测风险项 |
|--------|----------|------------|
| Nacos | 8848 | 未授权访问、敏感配置泄露 |
| XXL-Job | 8080 | 未授权执行、任务管理面板 |
| Spring Boot Admin | 8080/8090 | 端点暴露、Actuator 敏感路径 |
| Apache Druid | 8090 | 未授权监控面板 |
| Grafana | 3000 | 默认口令、敏感Dashboard |
| Redis | 6379 | 未授权访问 |
| Jenkins | 8080 | 未授权脚本执行 |
| Elasticsearch | 9200 | 敏感索引未授权访问 |
| RabbitMQ | 15672 | 管理界面未授权 |
| Apollo | 8070 | 配置中心未授权访问 |

> 📌 更多中间件持续添加中，欢迎提交 PR 扩充规则库。

## 📦 安装

```bash
# 克隆仓库
git clone https://github.com/Kurokoy/XSSCAN.git
cd XSSCAN

# 安装依赖
pip install -r requirements.txt
```

## 🚀 快速开始

### 扫描单个目标

```bash
python xsscan.py -u http://example.com:8848
```

### 批量扫描

```bash
python xsscan.py -f urls.txt
```

### 输出报告

```bash
# JSON 格式
python xsscan.py -u http://example.com:8848 -o result.json

# HTML 格式
python xsscan.py -u http://example.com:8848 -o result.html --format html

# CSV 格式
python xsscan.py -u http://example.com:8848 -o result.csv --format csv
```

### 查看帮助

```bash
python xsscan.py --help
```

## ⚙️ 配置

扫描行为可通过 `config.yaml` 进行调整：

```yaml
# config.yaml
timeout: 10          # 请求超时时间（秒）
threads: 10           # 并发线程数
user_agent: "XSSCAN/1.0"
follow_redirect: true

# 扫描模块开关
modules:
  nacos: true
  xxljob: true
  springboot: true
  druid: true
  grafana: true
  redis: true
  jenkins: true
  elasticsearch: true
  rabbitmq: true
  apollo: true

# 自定义Headers
headers:
  Authorization: "Bearer xxxx"
```

## 📂 项目结构

```
XSSCAN/
├── xsscan.py              # 主入口
├── config.yaml             # 配置文件
├── requirements.txt       # Python依赖
├── modules/                # 扫描模块目录
│   ├── __init__.py
│   ├── nacos.py
│   ├── xxljob.py
│   ├── springboot.py
│   ├── druid.py
│   ├── grafana.py
│   └── ...
├── lib/                    # 核心库
│   ├── detector.py        # 检测引擎
│   ├── http_client.py      # HTTP客户端封装
│   └── reporter.py         # 报告生成器
├── output/                 # 扫描结果输出目录
└── README.md
```

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

- 发现新的中间件暴露问题？ → 提交 Issue
- 有新的检测规则或功能改进？ → 提交 PR
- 发现漏洞？ → 请参考 [SECURITY.md](SECURITY.md)

## ⚠️ 免责声明

本工具仅供**授权的安全测试与合规检查**使用。使用者须确保己方拥有对目标系统的合法扫描权限。未经常授权擅自扫描他人系统属于违法行为，使用者需自行承担一切后果。

## 📄 License

MIT License
