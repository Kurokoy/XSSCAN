#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
服务指纹库 & 收敛建议
常见端口 -> 服务信息 -> 风险说明 -> 收敛建议
"""

# 常见高危/中危端口（公网不应暴露）
HIGH_RISK_PORTS = {
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    110,   # POP3
    135,   # MSRPC
    139,   # NetBIOS
    143,   # IMAP
    445,   # SMB
    1433,  # MSSQL
    1521,  # Oracle
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    6379,  # Redis
    8080,  # HTTP Proxy / 中间件
    8443,  # HTTPS Alt
    9200,  # Elasticsearch
    9300,  # Elasticsearch
    11211, # Memcached
}

# 中危端口（视业务情况）
MEDIUM_RISK_PORTS = {
    53,    # DNS
    80,    # HTTP
    443,   # HTTPS
    3000,  # Grafana / Devtools
    5672,  # RabbitMQ
    6379,  # Redis
    8000,  # Django / Spring Boot
    8081,  # HTTP Alt
    8088,  # HTTP Alt
    8090,  # HTTP Alt
    8091,  # HTTP Alt
    8443,  # HTTPS Alt
    8761,  # Eureka
    8848,  # Nacos
    9000,  # SonarQube / XXL-Job
    9001,  # HTTP Alt
    9090,  # Prometheus / Devtools
    9092,  # Kafka
    9200,  # Elasticsearch
    9300,  # Elasticsearch
    9943,  # HTTPS Alt
    10000, # Webmin
}

# 常见端口 -> 服务指纹信息
PORT_SERVICE_DB = {
    # === 高危端口 ===
    21: {
        "service": "FTP",
        "risk_level": "high",
        "description": "FTP 文件传输服务",
        "convergence": "如无文件传输必要，建议限制 21 端口至内网，如必须开放则强制使用 SFTP（22）替代，关闭匿名访问，启用 TLS 加密。",
    },
    22: {
        "service": "SSH",
        "risk_level": "high",
        "description": "SSH 远程登录服务",
        "convergence": "禁止密码登录，强制使用密钥认证；限制来源 IP；如无需公网访问建议将 SSH 收敛至内网 VPN 跳板机。",
    },
    23: {
        "service": "Telnet",
        "risk_level": "high",
        "description": "Telnet 明文远程登录（极危险）",
        "convergence": "立即停止使用 Telnet，全面切换至 SSH。如因 legacy 设备无法替换，需通过网络层 ACL 严格限制来源 IP。",
    },
    25: {
        "service": "SMTP",
        "risk_level": "high",
        "description": "邮件发送服务（Sendmail/Postfix）",
        "convergence": "邮件服务建议由云厂商托管（SES/SendGrid）。如自建，需开启 STARTTLS，禁用 Open Relay，配置 SPF/DKIM/DMARC。",
    },
    110: {
        "service": "POP3",
        "risk_level": "high",
        "description": "邮件收取协议（明文）",
        "convergence": "POP3 明文协议风险高，建议关闭。迁移至 IMAPS（993）或使用云邮件服务（Google Workspace/企业微信）。",
    },
    135: {
        "service": "MSRPC",
        "risk_level": "high",
        "description": "Microsoft RPC 端口",
        "convergence": "该端口常被用于内网横向渗透。建议通过防火墙 ACL 彻底阻断来自公网的访问。",
    },
    139: {
        "service": "NetBIOS / SMB",
        "risk_level": "high",
        "description": "NetBIOS 和 SMB 文件共享",
        "convergence": "139/445 联合利用可导致远程代码执行。必须通过安全组/防火墙ACL完全阻断公网访问，或确认无业务必要后关闭 NetBIOS。",
    },
    143: {
        "service": "IMAP",
        "risk_level": "high",
        "description": "邮件访问协议（明文）",
        "convergence": "明文 IMAP 建议关闭，迁移至 IMAPS（993）。如使用邮件服务，建议使用企业云邮件替代自建。",
    },
    445: {
        "service": "SMB",
        "risk_level": "high",
        "description": "SMB 文件共享（永恒之蓝漏洞载体）",
        "convergence": "该端口绝对不应暴露在公网。立即通过安全组/防火墙阻断，并确认内网是否需要 SMB 签名防御。",
    },
    1433: {
        "service": "MSSQL",
        "risk_level": "high",
        "description": "Microsoft SQL Server 数据库",
        "convergence": "数据库绝对不应暴露公网。立即收回公网访问权限，改为内网通过 VPN/跳板机访问；强制 RSA 加密连接，禁用 sa 账户弱密码。",
    },
    1521: {
        "service": "Oracle DB",
        "risk_level": "high",
        "description": "Oracle 数据库监听端口",
        "convergence": "数据库不应暴露公网。收敛至内网，禁用 Listener 远程管理，启用 Oracle Advanced Security 加密。",
    },
    3306: {
        "service": "MySQL",
        "risk_level": "high",
        "description": "MySQL 数据库",
        "convergence": "数据库端口不应暴露公网。立即收回公网权限，改为内网访问；强制 localhost-only 绑定（bind-address=127.0.0.1），启用强密码策略。",
    },
    3389: {
        "service": "RDP",
        "risk_level": "high",
        "description": "Windows 远程桌面协议",
        "convergence": "RDP 是勒索软件和横向渗透的常见入口。强烈建议关闭公网 RDP，改为 VPN 或跳板机登录；如必须开放，务必开启 Network Level Authentication（NLA）。",
    },
    5432: {
        "service": "PostgreSQL",
        "risk_level": "high",
        "description": "PostgreSQL 数据库",
        "convergence": "数据库不应暴露公网。改为内网访问，禁用 trust 认证模式，强制 md5 或 scram-sha-256 认证，配置 pg_hba.conf 限制来源 IP。",
    },
    5900: {
        "service": "VNC",
        "risk_level": "high",
        "description": "VNC 远程桌面",
        "convergence": "VNC 协议无内置加密，是常见攻击目标。建议关闭公网访问，替换为 VPN + SSH 跳板方式；如必须使用，启用 VNC Password 并通过 SSH 隧道访问。",
    },
    6379: {
        "service": "Redis",
        "risk_level": "high",
        "description": "Redis 内存数据库（未授权访问风险）",
        "convergence": "Redis 未授权访问可导致服务器被控。必须配置强密码（requirepass），禁用危险命令（FLUSHALL/FLUSHDB/KEYS），禁止 bind 0.0.0.0，改为内网访问。",
    },
    11211: {
        "service": "Memcached",
        "risk_level": "high",
        "description": "Memcached 缓存服务（未授权访问风险）",
        "convergence": "Memcached 未授权可导致敏感数据泄露。必须启用 SASL 认证，绑定 localhost；如跨机器访问，通过防火墙限制来源 IP。",
    },
    # === 中危端口 ===
    53: {
        "service": "DNS",
        "risk_level": "medium",
        "description": "域名解析服务（DNS Server）",
        "convergence": "DNS 服务如无公网解析必要，建议关闭53端口；如作为递归解析器，则限制仅对内部网络地址响应。",
    },
    80: {
        "service": "HTTP",
        "risk_level": "medium",
        "description": "Web 服务（HTTP 明文）",
        "convergence": "如无 HTTP 服务需求，建议关闭 80 端口；如提供 Web 服务，强制重定向至 HTTPS；配合 WAF 防护。",
    },
    443: {
        "service": "HTTPS",
        "risk_level": "medium",
        "description": "Web 服务（HTTPS 加密）",
        "convergence": "HTTPS 服务需确认是否在用，如无用则关闭；启用 TLS 1.2+；配合证书透明度监控；建议前置 WAF。",
    },
    3000: {
        "service": "Grafana / Node-Exporter / DevTools",
        "risk_level": "medium",
        "description": "常见运维工具默认端口（Grafana/Prometheus/DroneCI）",
        "convergence": "Grafana 等运维面板默认弱口令问题严重。建议仅内网访问；如需公网访问，强制 HTTPS + 强密码 + IP 白名单；禁止开放 /login API。",
    },
    5672: {
        "service": "RabbitMQ",
        "risk_level": "medium",
        "description": "RabbitMQ 消息队列",
        "convergence": "RabbitMQ 默认 guest/guest 弱口令风险。建议禁用默认账户，启用 TLS 认证，配置防火墙限制来源 IP，禁用 management 插件公网访问。",
    },
    8000: {
        "service": "Django / Spring Boot / Http Server",
        "risk_level": "medium",
        "description": "常见 Web 框架默认管理/调试端口",
        "convergence": "8000 端口常为 Django Debug 模式或 Spring Boot Actuator。确认是否为业务端口，关闭不必要的调试接口，前置 WAF 或 VPN。",
    },
    8080: {
        "service": "HTTP Proxy / Tomcat / 中间件",
        "risk_level": "medium",
        "description": "HTTP 代理或 Java 中间件默认端口",
        "convergence": "8080 常暴露 Tomcat 管理后台、API 服务或代理服务。确认是否为业务端口；非必要则限制来源 IP；禁止 /manager/html 等管理路径公网访问。",
    },
    8081: {
        "service": "HTTP Alt / Jenkins / Confluence",
        "risk_level": "medium",
        "description": "HTTP 备用端口，常见 Jenkins/Confluence/Artifactory",
        "convergence": "DevOps 工具（Jenkins/Confluence）常在 8081 部署，默认弱口令或未授权访问风险高。建议改为内网访问，强制 HTTPS + 强密码，禁用注册功能。",
    },
    8088: {
        "service": "HTTP Alt / Hadoop / Splunk",
        "risk_level": "medium",
        "description": "常见数据平台管理界面（Apache Hadoop ResourceManager/Splunk）",
        "convergence": "Hadoop/Splunk 管理界面暴露风险高（未授权执行 job/查询数据）。确认业务必要性，非必要则关闭；如需开放，严格 IP 白名单 + 强制认证。",
    },
    8090: {
        "service": "HTTP Alt / XXL-Job / Druid",
        "risk_level": "medium",
        "description": "常见中间件管理面板（XXL-Job/Druid/Apollo）",
        "convergence": "Druid/XXL-Job 未授权访问可导致任务执行和数据查询。确认是否为业务端口，关闭未授权访问路径，配置 IP 白名单。",
    },
    8091: {
        "service": "HTTP Alt / Kibana / SonarQube",
        "risk_level": "medium",
        "description": "常见运维平台（Kibana/SonarQube/Jenkins）",
        "convergence": "运维平台建议内网访问，如需公网访问则强制认证 + IP 白名单；SonarQube 注意默认管理员弱口令。",
    },
    8443: {
        "service": "HTTPS Alt / Tomcat / Zuul",
        "risk_level": "medium",
        "description": "HTTPS 备用端口（常见 Tomcat/Admin Dashboard）",
        "convergence": "8443 常用于管理后台 HTTPS。确认是否为业务端口；非必要则限制来源 IP；建议使用标准 443 端口统一入口。",
    },
    8761: {
        "service": "Eureka",
        "risk_level": "medium",
        "description": "Spring Cloud Eureka 服务注册中心",
        "convergence": "Eureka 未授权访问可导致微服务元数据泄露。建议关闭 management 端点公网访问，启用认证，限制注册来源。",
    },
    8848: {
        "service": "Nacos",
        "risk_level": "medium",
        "description": "Nacos 服务发现与配置中心（默认无认证）",
        "convergence": "Nacos 未授权可导致数据库密码/密钥等敏感配置泄露。必须启用认证（nacos.core.auth.enabled=true），限制 8848 端口来源 IP，关闭公网访问。",
    },
    9000: {
        "service": "SonarQube / XXL-Job / Portainer",
        "risk_level": "medium",
        "description": "代码审查/任务调度/Docker 管理平台",
        "convergence": "DevOps 平台建议内网访问；如需公网访问，必须强制 HTTPS + 强密码 + IP 白名单；禁止开放未授权 API 端点。",
    },
    9001: {
        "service": "HTTP Alt / Cassandra / Supervisor",
        "risk_level": "medium",
        "description": "常见数据库或进程管理工具",
        "convergence": "确认是否为业务端口；Supervisor XMLRPC 未授权可执行命令，建议限制 IP + 强制认证。",
    },
    9090: {
        "service": "Prometheus / Devtools",
        "risk_level": "medium",
        "description": "Prometheus 监控 / HTTP 默认管理端口",
        "convergence": "Prometheus 监控数据可间接反映业务规模。建议内网访问；如需开放配置 /metrics 端点，限制查询参数暴露；添加认证层。",
    },
    9092: {
        "service": "Kafka",
        "risk_level": "medium",
        "description": "Apache Kafka 消息队列",
        "convergence": "Kafka 默认无认证风险（可读写任意 topic）。必须启用 SASL/SSL 认证，配置防火墙限制来源 IP，禁用 JMX 端口（1099）。",
    },
    9200: {
        "service": "Elasticsearch",
        "risk_level": "medium",
        "description": "Elasticsearch 搜索引擎",
        "convergence": "Elasticsearch 未授权可查询全部数据、建立索引。建议关闭 X-Pack Security 公开访问；启用认证；配置 network.host=127.0.0.1；禁止公网访问kopf和head插件。",
    },
    9300: {
        "service": "Elasticsearch Transport",
        "risk_level": "medium",
        "description": "Elasticsearch 节点间通信协议",
        "convergence": "9300 为 ES 节点通信端口，不应暴露公网。绑定内网网卡；配置防火墙仅允许集群内部 IP 访问。",
    },
    9943: {
        "service": "HTTPS Alt / UAA Platform",
        "risk_level": "medium",
        "description": "常见 Cloud Foundry UAA 或定制 HTTPS 服务",
        "convergence": "确认服务身份；非必要则关闭；建议统一使用标准 443 端口。",
    },
    10000: {
        "service": "Webmin / Ajenti",
        "risk_level": "medium",
        "description": "Web 服务器管理面板（Webmin/Ajenti）",
        "convergence": "Webmin 历史漏洞较多。建议完全关闭公网访问，改为内网跳板机访问；如必须开放，强制 HTTPS + 强密码 + IP 白名单。",
    },
    15672: {
        "service": "RabbitMQ Management",
        "risk_level": "medium",
        "description": "RabbitMQ 管理界面",
        "convergence": "RabbitMQ 管理界面默认 guest/guest 弱口令。建议禁用默认账户，启用 TLS + 强密码，限制来源 IP；非必要则关闭。",
    },
    15692: {
        "service": "RabbitMQ Prometheus Exporter",
        "risk_level": "low",
        "description": "RabbitMQ Prometheus 指标导出端口",
        "convergence": "确认是否为 Prometheus 抓取需要；如不需要则关闭；如需要，确保防火墙限制 Prometheus 服务器 IP 访问。",
    },
    16379: {
        "service": "Redis Cluster",
        "risk_level": "high",
        "description": "Redis Cluster 节点通信端口",
        "convergence": "Redis Cluster 端口不应暴露公网。配置防火墙限制为集群内部 IP；启用认证（cluster-enabled=yes + requirepass）。",
    },
    6380: {
        "service": "Redis（TLS）",
        "risk_level": "high",
        "description": "Redis TLS 加密连接端口",
        "convergence": "即使有 TLS，仍需强密码 + IP 白名单；如无跨机房访问需求，建议仅内网绑定。",
    },
    8070: {
        "service": "Apollo Config Center",
        "risk_level": "medium",
        "description": "Apollo 配置中心管理端口",
        "convergence": "Apollo 未授权可导致所有环境配置泄露。启用管理员认证，限制 8070 端口来源 IP；敏感项目建议加入 VPN。",
    },
    27017: {
        "service": "MongoDB",
        "risk_level": "high",
        "description": "MongoDB 数据库",
        "convergence": "MongoDB 未授权访问可导致数据批量泄露。必须启用 --auth，配置 bind_ip=127.0.0.1，强制 SCRAM-SHA-1 认证，禁止公网访问。",
    },
}

# 全端口清单（常见端口列表，用于全端口扫描）
COMMON_PORTS = sorted({
    # Web 相关
    80, 443, 8080, 8443, 8000, 8001, 8008, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097,
    8098, 8099, 8100, 8101, 8102, 8103, 8104, 8105, 8106, 8107, 8108, 8109,
    8110, 8111, 8112, 8118, 8120, 8123, 8128, 8130, 8131, 8132, 8139, 8140,
    8148, 8150, 8160, 8161, 8170, 8171, 8180, 8181, 8190, 8191, 8192, 8193,
    8194, 8200, 8201, 8202, 8300, 8301, 8302, 8303, 8400, 8443, 8444, 8445,
    8446, 8447, 8448, 8449, 8450, 8480, 8484, 8500, 8530, 8531, 8800, 8808,
    8809, 8810, 8880, 8881, 8888, 8889, 8890, 8891, 8892, 8893, 8894, 8896,
    8899, 8900, 8901, 8902, 8903, 8980, 8983, 8984, 9000, 9001, 9002, 9003,
    9009, 9010, 9020, 9021, 9022, 9023, 9024, 9025, 9026, 9027, 9028, 9029,
    9030, 9042, 9043, 9050, 9051, 9060, 9070, 9080, 9081, 9090, 9091, 9092,
    9093, 9094, 9095, 9096, 9097, 9098, 9099, 9100, 9101, 9102, 9110, 9111,
    9200, 9201, 9202, 9243, 9250, 9300, 9301, 9302, 9303, 9306, 9308, 9309,
    9310, 9311, 9312, 9390, 9391, 9392, 9393, 9394, 9395, 9396, 9397, 9398,
    9399, 9400, 9418, 9443, 9500, 9530, 9595, 9600, 9630, 9643, 9650, 9695,
    9700, 9710, 9761, 9762, 9797, 9800, 9843, 9876, 9877, 9878, 9898, 9900,
    9943, 9950, 9960, 9966, 9970, 9990, 9991, 9992, 9993, 9994, 9995, 9996,
    9997, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007,
    10008, 10009, 10010, 10080, 10081, 10082, 10110, 10160, 10250, 10255,
    10280, 10281, 10443, 10554, 10592, 10628, 10880, 11001, 11210, 11211,
    11235, 11311, 12000, 12111, 12345, 12443, 13000, 13001, 13002, 13003,
    13004, 13005, 13006, 13007, 13008, 13009, 13010, 13011, 13012, 13013,
    13014, 13015, 13016, 13017, 13018, 13019, 13020, 13021, 13030, 13306,
    13443, 13500, 14000, 14330, 14369, 15000, 15002, 15004, 15200, 15201,
    15291, 15345, 15672, 15692, 16000, 16001, 16080, 16200, 16379, 16443,
    17000, 17001, 17002, 17500, 17600, 18000, 18001, 18080, 18081, 18091,
    18092, 18093, 18094, 18095, 18096, 18097, 18098, 18099, 18100, 18500,
    18600, 18700, 18800, 18888, 19000, 19080, 19081, 19083, 19300, 19443,
    19500, 19501, 19888, 20000, 20001, 20002, 20003, 20010, 20011, 20080,
    20101, 20547, 20880, 21000, 21001, 21100, 21101, 2181, 22000, 22222,
    2375, 2376, 2379, 2380, 24000, 24443, 24554, 25000, 25001, 25002, 25003,
    25004, 25005, 25006, 25007, 25008, 25009, 25010, 25011, 25012, 25013,
    25014, 25015, 25016, 25017, 25018, 25019, 25020, 25565, 26000, 26001,
    26002, 26003, 26004, 26005, 26006, 26007, 26008, 26009, 26010, 26011,
    26012, 26013, 26014, 26015, 26016, 26017, 26018, 26019, 26020, 26021,
    26022, 26023, 26024, 27000, 27001, 27002, 27003, 27004, 27005, 27017,
    27018, 27019, 27374, 28000, 28001, 28002, 28003, 28004, 28005, 28006,
    28007, 28008, 28009, 28010, 29000, 29001, 29015, 30000, 30001, 30002,
    30003, 30004, 30005, 30080, 31000, 31001, 31002, 31003, 31004, 31005,
    31006, 31007, 31008, 31009, 31010, 32000, 32001, 32002, 32003, 32004,
    32005, 32006, 32007, 32008, 32009, 32010, 33000, 33001, 33002, 33003,
    33004, 33005, 33006, 33060, 33434, 33600, 34000, 35000, 35001, 35002,
    35003, 35004, 35005, 35006, 35007, 35008, 35009, 35010, 35500, 36000,
    36001, 36002, 36003, 36004, 36005, 36006, 36007, 36008, 36009, 36010,
    37000, 38000, 39000, 40000, 40001, 40002, 40003, 40004, 40005, 40006,
    40007, 40008, 40009, 40010, 41000, 42000, 43000, 44000, 45000, 45000,
    45001, 45002, 45003, 45004, 45005, 45006, 45007, 45008, 45009, 45010,
    46000, 47000, 48000, 49000, 49100, 49152, 50000, 50001, 50002, 50003,
    50004, 50005, 50006, 50007, 50008, 50009, 50010, 50030, 50060, 50070,
    50075, 50090, 51000, 51001, 51002, 51003, 51004, 51005, 51006, 51007,
    51008, 51009, 51010, 51413, 52000, 53000, 54000, 55000, 55555, 55556,
    56000, 57000, 58000, 59000, 60000, 60010, 60020, 60030, 60080, 60081,
    60090, 60100, 60101, 60102, 61000, 61100, 62000, 62100, 62200, 63000,
    63100, 63200, 63300, 64000, 65000,

    # 数据库 & 存储
    1433, 1521, 3306, 5000, 5432, 5672, 6379, 6380, 8082, 8091, 9160,
    10000, 11211, 15672, 16379, 27017, 33060,

    # 协议 & 基础设施
    21, 22, 23, 25, 53, 67, 68, 69, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 445, 465, 514, 515, 587, 636, 993, 995, 1080,
    1433, 1434, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    2181, 2375, 2376, 2377, 2379, 2380, 3000, 3306, 3389, 4369, 5432,
    5666, 5672, 5673, 5900, 5901, 5984, 5985, 5986, 6379, 6380, 7000,
    7001, 7002, 7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010, 7199,
    8000, 8001, 8008, 8009, 8010, 8020, 8021, 8022, 8025, 8030, 8031,
    8040, 8042, 8048, 8060, 8069, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096,
    8097, 8098, 8099, 8100, 8108, 8110, 8123, 8138, 8139, 8140, 8161,
    8180, 8181, 8200, 8222, 8243, 8280, 8281, 8291, 8300, 8333, 8334,
    8400, 8443, 8444, 8445, 8500, 8530, 8531, 8600, 8686, 8761, 8765,
    8778, 8800, 8834, 8848, 8888, 8889, 8983, 9000, 9001, 9002, 9009,
    9010, 9042, 9043, 9050, 9080, 9081, 9090, 9091, 9092, 9093, 9094,
    9095, 9096, 9097, 9098, 9099, 9100, 9101, 9102, 9110, 9111, 9200,
    9201, 9202, 9203, 9204, 9205, 9206, 9207, 9208, 9209, 9210, 9211,
    9212, 9213, 9214, 9215, 9216, 9217, 9218, 9219, 9220, 9221, 9222,
    9243, 9300, 9301, 9302, 9303, 9304, 9305, 9306, 9307, 9308, 9309,
    9310, 9311, 9312, 9313, 9314, 9315, 9316, 9317, 9318, 9319, 9320,
    9390, 9391, 9392, 9393, 9394, 9395, 9396, 9397, 9398, 9399, 9400,
    9418, 9443, 9500, 9530, 9600, 9630, 9643, 9650, 9695, 9700, 9761,
    9762, 9797, 9800, 9843, 9850, 9876, 9877, 9878, 9898, 9900, 9943,
    9950, 9990, 9991, 9992, 9993, 9994, 9995, 9996, 9997, 9998, 9999,
    10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10008, 10009,
    10010, 10080, 10250, 10255, 11211, 11235, 12000, 12345, 12443, 13306,
    13443, 14000, 14330, 14369, 15000, 15002, 15200, 15201, 15291, 15672,
    15692, 16000, 16001, 16200, 16379, 16443, 17000, 17001, 17002, 17500,
    18000, 18001, 18080, 18081, 19000, 19080, 19081, 19443, 20000, 20001,
    20002, 20880, 21000, 21001, 21100, 21101, 22000, 22222, 2375, 2376,
    2379, 2380, 25000, 25001, 25002, 25003, 25004, 25005, 25565, 26000,
    27000, 27001, 27002, 27003, 27004, 27005, 27017, 27018, 27019, 28000,
    29000, 29015, 30000, 30001, 30002, 31000, 32000, 33000, 34000, 35000,
    36000, 37000, 38000, 39000, 40000, 41000, 42000, 43000, 44000, 45000,
    46000, 47000, 48000, 49000, 49152, 50000, 50001, 50002, 50003, 50030,
    50060, 50070, 50075, 50090, 51000, 51413, 52000, 53000, 54000, 55000,
    55555, 56000, 57000, 58000, 59000, 60000, 60010, 60020, 60030, 60080,
    60081, 61000, 62000, 63000, 64000, 65000,
})


def get_port_info(port):
    """查询端口信息，返回指纹 dict；未知端口返回 None"""
    return PORT_SERVICE_DB.get(port)


def get_risk_level(port):
    """获取端口风险等级"""
    info = get_port_info(port)
    if info:
        return info.get("risk_level", "low")
    if port in HIGH_RISK_PORTS:
        return "high"
    if port in MEDIUM_RISK_PORTS:
        return "medium"
    return "low"


def get_convergence_suggestion(port):
    """获取端口收敛建议"""
    info = get_port_info(port)
    if info:
        return info.get("convergence", "建议确认该端口服务是否为业务必要，如非必要建议关闭。")
    # 未知端口
    return "该端口为未知服务。建议使用 nmap 或浏览器确认服务身份；如非业务必要，建议通过防火墙关闭该端口或限制来源 IP。"


def build_port_report(host, open_ports, schemes=None, status_codes=None):
    """
    为一组开放端口生成完整的资产报告
    host: IP 地址
    open_ports: sorted list of int
    schemes: dict {port: scheme} 可选
    status_codes: dict {port: int} 可选，HTTP 状态码
    返回: list[dict]
    """
    schemes = schemes or {}
    status_codes = status_codes or {}
    report = []
    for port in sorted(open_ports):
        info = get_port_info(port)
        service = info["service"] if info else "Unknown"
        risk = get_risk_level(port)
        suggestion = get_convergence_suggestion(port)
        scheme = schemes.get(port, "http")
        url = f"{scheme}://{host}:{port}"

        entry = {
            "host": host,
            "port": port,
            "service": service,
            "risk_level": risk,
            "status_code": status_codes.get(port),
            "url": url,
            "description": info["description"] if info else "未知服务，建议人工确认",
            "suggestion": suggestion,
        }
        report.append(entry)

    return report
