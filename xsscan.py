#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XSSCAN - Exposure Surface Scan
Author: Kurokoy & Hermes Agent
Linux only tool for scanning exposed middleware on public endpoints
"""

import sys
import os
import argparse
from colorama import init as colorama_init

# Fix colorama on Windows subsys
try:
    colorama_init(autoreset=True)
except Exception:
    pass

from lib.detector import Detector
from lib.reporter import Reporter
from lib.http_client import HttpClient


BANNER = """
   ▄▄▄▄    ██▓    ▄▄▄       ▄████▄   ██ ▄█▓██▓██▓ ██▓  ▄▄▄       █    ██  ██▓  ▄▄▄█████▓
   ▓█████▄▓██▒   ▒████▄    ▒██▀ ▀█   ██▄█▒▓██▒▓██▒▓██▒  ▒████▄     ██  ▓██▒▓██▒  ▓  ██▒ ▓▒
   ▒██▒ ▄██▒██░   ▒██  ▀█▄  ▒▓█    ▄ ▓███▄░▒██▒▒██░  ▒██  ▀█▄  ▓██  ▒██░▒██░  ▒ ▓██░ ▒░
   ▒██░█▀  ▒██░   ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄░██░▒██░  ░██▄▄▄▄██ ▓▓█  ░██░▒██░  ░ ▓██▓ ░
   ░▓█  ▀█▓░██████▒▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄░██░░██████▒▓█   ▓██▒▒▒█████▓ ░██████▒▒██▒ ░
   ░▒▓███▀▒░ ▒░▓  ░▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒░ ▒░░ ▒░▓  ░▒▒   ▓▒░░▒▓▒ ▒ ▒ ░ ▒░▓  ░▒ ░░
   ▒░▒   ░ ░ ░ ▒  ░ ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░░ ░░ ░ ▒  ░ ▒   ▒▒ ░░▒░▒ ░ ░ ░ ▒  ░  ░
"""

AVAILABLE_MODULES = {
    "nacos":      "Nacos (8848)        - 未授权访问 / 敏感配置",
    "xxljob":     "XXL-Job (8080)      - 未授权任务执行",
    "springboot": "Spring Boot (8080)  - Actuator 敏感端点",
    "druid":      "Druid (8090)        - 未授权监控面板",
    "grafana":    "Grafana (3000)      - 默认口令 / 敏感Dashboard",
    "redis":      "Redis (6379)        - 未授权访问",
    "jenkins":    "Jenkins (8080)      - 未授权脚本执行",
    "elasticsearch": "Elasticsearch (9200) - 敏感索引未授权",
    "rabbitmq":   "RabbitMQ (15672)   - 管理界面未授权",
    "apollo":     "Apollo (8070)       - 配置中心未授权",
}


def print_banner():
    for line in BANNER.split('\n'):
        print(f'\033[96m{line}\033[0m')
    print(f'  \033[33mExposure Surface Scan — v1.0.0\033[0m\n')


def list_modules():
    print("\n[可用扫描模块]\n")
    for key, desc in AVAILABLE_MODULES.items():
        print(f"  {key:16s}  {desc}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="XSSCAN — 面向公网入口的暴露面扫描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
使用示例:
  %(prog)s -u http://example.com:8848                   扫描单个目标(自动检测)
  %(prog)s -u http://example.com -m nacos               指定扫描 Nacos
  %(prog)s -u http://example.com -m nacos,xxljob         同时扫描 Nacos + XXL-Job
  %(prog)s -f urls.txt -m nacos                         批量扫描 Nacos
  %(prog)s --list                                        列出所有可用模块

支持的模块: {' | '.join(AVAILABLE_MODULES.keys())}
"""
    )
    parser.add_argument("-u", "--url", help="目标 URL (例: http://example.com:8848)")
    parser.add_argument("-f", "--file", help="URL 列表文件 (每行一个)")
    parser.add_argument(
        "-m", "--modules",
        help=f"指定扫描的模块，逗号分隔 (例: nacos,xxljob)。留空则自动检测所有已启用模块"
    )
    parser.add_argument(
        "--list", action="store_true",
        help="列出所有可用扫描模块并退出"
    )
    parser.add_argument(
        "-o", "--output",
        help="结果输出文件路径 (默认: output/ 时间戳.json)"
    )
    parser.add_argument(
        "--format", choices=["json", "html", "csv"], default="json",
        help="输出格式 (默认: json)"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=10,
        help="并发线程数 (默认: 10)"
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="请求超时秒数 (默认: 10)"
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="禁用彩色输出"
    )

    args = parser.parse_args()

    if args.no_color:
        # 简单关闭颜色
        os.environ["ANSI_COLORS_DISABLED"] = "1"

    print_banner()

    if args.list:
        list_modules()
        sys.exit(0)

    if not args.url and not args.file:
        parser.print_help()
        print("\n[错误] 必须提供 -u (URL) 或 -f (URL列表文件)\n")
        sys.exit(1)

    # 解析目标列表
    targets = []
    if args.url:
        targets.append(args.url.rstrip("/"))
    if args.file:
        if not os.path.exists(args.file):
            print(f"[错误] 文件不存在: {args.file}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line.rstrip("/"))

    if not targets:
        print("[错误] 没有有效的扫描目标")
        sys.exit(1)

    # 解析模块
    if args.modules:
        selected = [m.strip() for m in args.modules.split(",")]
        invalid = [m for m in selected if m not in AVAILABLE_MODULES]
        if invalid:
            print(f"[错误] 未知模块: {', '.join(invalid)}")
            print(f"可用模块: {', '.join(AVAILABLE_MODULES.keys())}")
            sys.exit(1)
        module_names = selected
    else:
        # 默认全部
        module_names = list(AVAILABLE_MODULES.keys())

    print(f"[信息] 目标数量: {len(targets)}")
    print(f"[信息] 扫描模块: {', '.join(module_names)}")
    print(f"[信息] 并发线程: {args.threads}")
    print()

    # 初始化检测器
    config = {
        "threads": args.threads,
        "timeout": args.timeout,
    }
    http_client = HttpClient(timeout=config["timeout"])
    detector = Detector(http_client, module_names, config)
    reporter = Reporter()

    # 执行扫描
    all_results = []
    for target in targets:
        print(f"\n[扫描] {target}")
        results = detector.scan(target)
        all_results.extend(results)
        reporter.add_results(target, results)

    # 输出报告
    output_file = args.output
    if not output_file:
        import datetime
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"output/scan_{ts}.{args.format}"

    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else "output", exist_ok=True)
    reporter.save(output_file, args.format)
    print(f"\n[完成] 结果已保存: {output_file}")
    print(f"[统计] 共发现 {reporter.total_findings()} 个暴露风险点\n")


if __name__ == "__main__":
    main()
