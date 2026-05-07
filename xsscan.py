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
import datetime

try:
    from colorama import init as colorama_init
    colorama_init(autoreset=True)
except Exception:
    pass

from lib.detector import Detector
from lib.reporter import Reporter
from lib.http_client import HttpClient
from lib.port_scanner import PortScanner, resolve_target_full
from lib.notifier import WeChatNotifier


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
    "nacos":        "Nacos (8848)        - 未授权访问 / 敏感配置",
    "xxljob":       "XXL-Job (8080)      - 未授权任务执行",
    "springboot":   "Spring Boot (8080)  - Actuator 敏感端点",
    "druid":        "Druid (8090)        - 未授权监控面板",
    "grafana":      "Grafana (3000)      - 默认口令 / 敏感Dashboard",
    "redis":        "Redis (6379)        - 未授权访问",
    "jenkins":      "Jenkins (8080)      - 未授权脚本执行",
    "elasticsearch":"Elasticsearch (9200) - 敏感索引未授权",
    "rabbitmq":     "RabbitMQ (15672)   - 管理界面未授权",
    "apollo":       "Apollo (8070)       - 配置中心未授权",
}


def print_banner():
    for line in BANNER.split('\n'):
        print(f'\033[96m{line}\033[0m')
    print(f'  \033[33mExposure Surface Scan — v1.1.0\033[0m\n')


def list_modules():
    print("\n[ 可用扫描模块 ]\n")
    for key, desc in AVAILABLE_MODULES.items():
        print(f"  {key:16s}  {desc}")
    print()


def parse_targets(args):
    """
    解析目标列表，支持:
    - 纯 IP/域名（如 1.2.3.4 / example.com）
    - 带端口 URL（如 http://1.2.3.4:8848）
    返回: list[str]  每项为 http(s)://host:port 格式
    """
    raw_targets = []

    if args.url:
        raw_targets.append(args.url)

    if args.file:
        if not os.path.exists(args.file):
            print(f"[错误] 文件不存在: {args.file}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    raw_targets.append(line)

    # 去重
    raw_targets = list(dict.fromkeys(raw_targets))
    return raw_targets


def resolve_all_targets(raw_targets, modules, port_timeout=3, scan_timeout=10):
    """
    对所有原始目标进行端口扫描 + 协议检测
    返回: list[dict]  每项 = {host, port, scheme, module, url, target}
    """
    resolved = []
    for raw in raw_targets:
        raw = raw.strip()
        if not raw:
            continue

        host, port, scheme = resolve_target_full(raw)

        # 带端口/协议的完整 URL -> 直接检测协议
        if port:
            scheme = scheme or detect_scheme_quick(host, port, scan_timeout)
            entry = {
                "host": host,
                "port": port,
                "scheme": scheme,
                "url": f"{scheme}://{host}:{port}",
                "target": f"{scheme}://{host}:{port}",
            }
            resolved.append(entry)
            print(f"  [目标] {entry['url']}")
            continue

        # 纯 IP/域名 -> 端口扫描 + 协议检测
        print(f"\n[扫描端口] {host} ...")
        port_scanner = PortScanner(modules, {
            "timeout": scan_timeout,
            "port_scan_timeout": port_timeout,
        })
        results = port_scanner.scan(raw)
        if not results:
            print(f"  [无开放端口] {host}")
        for r in results:
            print(f"  [发现] {r['url']}  (模块候选: {r['module']})")
        resolved.extend(results)

    return resolved


def detect_scheme_quick(host, port, timeout=10):
    """快速检测 HTTP/HTTPS（先试 https）"""
    import urllib.parse
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}:{port}"
        try:
            resp = HttpClient(timeout=timeout).get(url)
            if resp and resp.status_code < 500:
                return scheme
        except Exception:
            pass
    return "http"


def main():
    parser = argparse.ArgumentParser(
        description="XSSCAN — 面向公网入口的暴露面扫描工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
使用示例:
  %(prog)s -u 1.2.3.4                           扫描单个 IP（自动扫描端口）
  %(prog)s -u http://1.2.3.4:8848               扫描指定端口目标
  %(prog)s -f targets.txt -m nacos,xxljob       批量扫描（自动端口扫描）
  %(prog)s -f targets.txt --port-only           仅做端口扫描，不做漏洞检测
  %(prog)s -u 1.2.3.4 --full-scan               全端口扫描（~700个端口）输出资产清单+收敛建议
  %(prog)s -u 1.2.3.4 --full-scan -o report.html --format html  生成 HTML 报告
  %(prog)s -u 1.2.3.4 --notify                           扫描完成后推送结果到企微机器人
  %(prog)s -u 1.2.3.4 --notify --webhook "https://..."   使用指定 Webhook 推送
  %(prog)s --list                               列出所有可用模块

支持的模块: {' | '.join(AVAILABLE_MODULES.keys())}
"""
    )
    parser.add_argument("-u", "--url", help="目标 URL 或 IP（例: 1.2.3.4 或 http://example.com:8848）")
    parser.add_argument("-f", "--file", help="目标列表文件（每行一个 IP 或域名）")
    parser.add_argument(
        "-m", "--modules",
        help=f"指定扫描的模块，逗号分隔（例: nacos,xxljob）。留空则自动检测所有模块"
    )
    parser.add_argument(
        "--list", action="store_true",
        help="列出所有可用扫描模块并退出"
    )
    parser.add_argument(
        "-o", "--output",
        help="结果输出文件路径（默认: output/ 时间戳.json）"
    )
    parser.add_argument(
        "--format", choices=["json", "html", "csv"], default="json",
        help="输出格式（默认: json）"
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=10,
        help="漏洞检测并发线程数（默认: 10）"
    )
    parser.add_argument(
        "--timeout", type=int, default=10,
        help="漏洞检测请求超时秒数（默认: 10）"
    )
    parser.add_argument(
        "--port-timeout", type=int, default=3,
        help="端口扫描超时秒数（默认: 3）"
    )
    parser.add_argument(
        "--port-only", action="store_true",
        help="仅做端口扫描，不执行漏洞检测"
    )
    parser.add_argument(
        "--full-scan", action="store_true",
        help="全端口扫描模式：扫描所有常见端口（~600个），输出完整端口资产清单与收敛建议"
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="禁用彩色输出"
    )
    parser.add_argument(
        "--webhook", default=None,
        help="企微机器人 Webhook 地址（支持直接传入 key=xxx 或完整 URL）"
    )
    parser.add_argument(
        "--notify", action="store_true",
        help="扫描完成后推送结果到企微机器人 Webhook"
    )

    args = parser.parse_args()

    if args.no_color:
        os.environ["ANSI_COLORS_DISABLED"] = "1"

    print_banner()

    if args.list:
        list_modules()
        sys.exit(0)

    if not args.url and not args.file:
        parser.print_help()
        print("\n[错误] 必须提供 -u（单目标）或 -f（目标列表文件）\n")
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
        module_names = list(AVAILABLE_MODULES.keys())

    # 解析目标
    raw_targets = parse_targets(args)
    if not raw_targets:
        print("[错误] 没有有效的扫描目标")
        sys.exit(1)

    print(f"[信息] 原始目标数量: {len(raw_targets)}")
    print(f"[信息] 扫描模块: {', '.join(module_names)}")

    # ── 全端口扫描模式（优先，不走中间件端口扫描流程）─────────────────────
    if args.full_scan:
        print("\n========== 全端口扫描 ==========\n")
        port_scanner = PortScanner(module_names, {
            "timeout": args.timeout,
            "port_scan_timeout": args.port_timeout,
        })
        reporter_port = Reporter()

        for raw in raw_targets:
            raw = raw.strip()
            if not raw:
                continue
            host, port, _ = resolve_target_full(raw)
            port_entries = port_scanner.full_scan(raw)
            if port_entries:
                print(f"[发现] {host} — {len(port_entries)} 个开放端口")
                reporter_port.add_port_inventory(host, port_entries)
                for entry in port_entries:
                    risk_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(entry.get("risk_level", ""), "⚪")
                    print(f"  {risk_emoji} {entry['port']:>6}  {entry['service']:<22}  {entry.get('risk_level', ''):<8}  {entry['url']}")
            else:
                print(f"[无开放端口] {host}")

        if reporter_port.total_open_ports() > 0:
            output_file = args.output
            if not output_file:
                ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = f"output/full_scan_{ts}.{args.format}"
            os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else "output", exist_ok=True)
            reporter_port.save(output_file, args.format)
            print(f"\n[完成] 全端口资产清单已保存: {output_file}")
            risk_sum = reporter_port.risk_summary()
            high_risk = risk_sum.get("high", 0)
            medium_risk = risk_sum.get("medium", 0)
            print(f"[统计] 共 {reporter_port.total_open_ports()} 个开放端口 | 🔴高危 {high_risk} | 🟡中危 {medium_risk}")
            if high_risk > 0:
                print(f"[警告] 高危端口数量 > 0，请尽快按收敛建议整改！")
            # ── 企微通知 ───────────────────────────────────────────────────
            if args.notify:
                notifier = WeChatNotifier(args.webhook)
                ok, msg = notifier.notify_scan_complete(
                    results=[],
                    port_inventory=reporter_port.port_inventory,
                    target=raw
                )
                print(f"[通知] {'✅' if ok else '❌'} 企微机器人: {msg}")
        else:
            print("\n[结束] 未发现任何开放端口\n")
            if args.notify:
                notifier = WeChatNotifier(args.webhook)
                ok, msg = notifier.send_markdown(
                    f"## 🛡️ XSSCAN 扫描完成\n\n**目标**: `{raw}`\n\n> 未发现任何开放端口。"
                )
                print(f"[通知] {'✅' if ok else '❌'} 企微机器人: {msg}")
        sys.exit(0)

    # ── 中间件端口扫描 + 协议检测 ──────────────────────────────────────
    print("\n========== 端口扫描 & 协议检测 ==========\n")
    resolved_targets = resolve_all_targets(
        raw_targets,
        module_names,
        port_timeout=args.port_timeout,
        scan_timeout=args.timeout,
    )

    if not resolved_targets:
        print("\n[结束] 未发现任何开放端口\n")
        if args.notify:
            notifier = WeChatNotifier(args.webhook)
            ok, msg = notifier.send_markdown(
                f"## 🛡️ XSSCAN 扫描完成\n\n**目标**: `{raw_targets[0]}`\n\n> 未发现任何开放端口。"
            )
            print(f"[通知] {'✅' if ok else '❌'} 企微机器人: {msg}")
        sys.exit(0)

    print(f"\n[信息] 共发现 {len(resolved_targets)} 个有效端点")

    # ── 仅端口扫描模式 ──────────────────────────────────────────────────
    if args.port_only:
        port_scanner = PortScanner(module_names, {
            "timeout": args.timeout,
            "port_scan_timeout": args.port_timeout,
        })
        reporter_port = Reporter()

        for raw in raw_targets:
            raw = raw.strip()
            if not raw:
                continue
            host, port, _ = resolve_target_full(raw)
            port_entries = port_scanner.full_scan(raw)
            if port_entries:
                print(f"[发现] {host} — {len(port_entries)} 个开放端口")
                reporter_port.add_port_inventory(host, port_entries)
                for entry in port_entries:
                    print(f"  {entry['port']:>6}  {entry['service']:<20}  {entry.get('risk_level', ''):<8}  {entry['url']}")
            else:
                print(f"[无开放端口] {host}")

        output_file = args.output
        if not output_file:
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"output/port_scan_{ts}.{args.format}"
        os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else "output", exist_ok=True)
        reporter_port.save(output_file, args.format)
        print(f"\n[完成] 端口扫描结果已保存: {output_file}\n")
        # ── 企微通知 ───────────────────────────────────────────────────
        if args.notify:
            notifier = WeChatNotifier(args.webhook)
            ok, msg = notifier.notify_scan_complete(
                results=[],
                port_inventory=reporter_port.port_inventory,
                target=raw
            )
            print(f"[通知] {'✅' if ok else '❌'} 企微机器人: {msg}")
        sys.exit(0)

    # 漏洞检测
    print("\n========== 漏洞检测 ==========\n")
    http_client = HttpClient(timeout=args.timeout)
    detector = Detector(http_client, module_names, {"threads": args.threads})
    reporter = Reporter()

    for entry in resolved_targets:
        target = entry["target"]
        print(f"\n[检测] {target}")
        findings = detector.scan(target)
        reporter.add_results(target, findings)

    # 全端口资产清单（同步执行，附加到同一个报告）
    print("\n========== 端口资产清单 ==========\n")
    port_scanner = PortScanner(module_names, {
        "timeout": args.timeout,
        "port_scan_timeout": args.port_timeout,
    })
    for raw in raw_targets:
        raw = raw.strip()
        if not raw:
            continue
        host, _, _ = resolve_target_full(raw)
        port_entries = port_scanner.full_scan(raw)
        if port_entries:
            reporter.add_port_inventory(host, port_entries)
            print(f"[发现] {host} — {len(port_entries)} 个开放端口")
            for entry in port_entries:
                risk_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(entry.get("risk_level", ""), "⚪")
                print(f"  {risk_emoji} {entry['port']:>6}  {entry['service']:<20}  {entry.get('risk_level', ''):<8}  {entry['url']}")
        else:
            print(f"[无开放端口] {host}")

    # 输出报告
    output_file = args.output
    if not output_file:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"output/scan_{ts}.{args.format}"
    os.makedirs(os.path.dirname(output_file) if os.path.dirname(output_file) else "output", exist_ok=True)
    reporter.save(output_file, args.format)
    print(f"\n[完成] 结果已保存: {output_file}")
    print(f"[统计] 共发现 {reporter.total_findings()} 个暴露风险点")
    if reporter.total_open_ports() > 0:
        risk_sum = reporter.risk_summary()
        print(f"[统计] 共发现 {reporter.total_open_ports()} 个开放端口 | 🔴高危 {risk_sum.get('high', 0)} | 🟡中危 {risk_sum.get('medium', 0)}")
        if risk_sum.get("high", 0) > 0:
            print(f"[警告] 高危端口数量 > 0，请尽快按收敛建议整改！")
    print()
    # ── 企微通知 ───────────────────────────────────────────────────
    if args.notify:
        notifier = WeChatNotifier(args.webhook)
        ok, msg = notifier.notify_scan_complete(
            results=reporter.results,
            port_inventory=reporter.port_inventory,
            target=", ".join(raw_targets)
        )
        print(f"[通知] {'✅' if ok else '❌'} 企微机器人: {msg}")


if __name__ == "__main__":
    main()
