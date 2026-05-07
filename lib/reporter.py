#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告生成器
支持 JSON / HTML / CSV 格式输出
包含两部分报告：
  1. 漏洞检测报告（vulnerability findings）
  2. 端口资产清单报告（port inventory + 收敛建议）
"""

import json
import csv
import os
from datetime import datetime


class Reporter:

    def __init__(self):
        self.results = []          # 漏洞检测结果 list[dict]
        self.target_map = {}        # target -> list[dict]
        self.port_inventory = []    # 端口资产清单 list[dict]
        self.port_inventory_host = ""  # 端口扫描所属主机

    def add_results(self, target, findings):
        """记录漏洞扫描结果"""
        self.results.extend(findings)
        self.target_map[target] = findings

    def add_port_inventory(self, host, port_entries):
        """
        记录全端口资产清单
        host: IP 地址
        port_entries: list[dict] 每个元素 = {port, service, risk_level, url, description, suggestion, ...}
        """
        self.port_inventory_host = host
        self.port_inventory = port_entries

    def total_findings(self):
        return len(self.results)

    def total_open_ports(self):
        return len(self.port_inventory)

    def risk_summary(self):
        """统计各风险等级端口数量"""
        high = medium = low = unknown = 0
        for entry in self.port_inventory:
            risk = entry.get("risk_level", "unknown")
            if risk == "high":
                high += 1
            elif risk == "medium":
                medium += 1
            elif risk == "low":
                low += 1
            else:
                unknown += 1
        return {"high": high, "medium": medium, "low": low, "unknown": unknown}

    def save(self, path, format="json"):
        """保存报告（同时包含漏洞 + 端口清单两部分）"""
        if format == "json":
            self._save_json(path)
        elif format == "html":
            self._save_html(path)
        elif format == "csv":
            self._save_csv(path)

    # ─── JSON ──────────────────────────────────────────────────────────────────

    def _save_json(self, path):
        report = {
            "tool": "XSSCAN",
            "version": "1.1.0",
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_findings": len(self.results),
                "total_open_ports": len(self.port_inventory),
                "risk_summary": self.risk_summary() if self.port_inventory else {},
            },
            "port_inventory": self.port_inventory,
            "vulnerability_findings": self.results,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

    # ─── HTML ──────────────────────────────────────────────────────────────────

    def _save_html(self, path):
        # ── 端口资产清单部分 ──────────────────────────────────────────────
        if self.port_inventory:
            port_rows = ""
            for entry in self.port_inventory:
                risk = entry.get("risk_level", "info")
                color_cls = {
                    "high": "risk-high",
                    "medium": "risk-medium",
                    "low": "risk-low",
                    "info": "risk-info",
                }.get(risk, "risk-info")
                port_rows += f"""
                <tr>
                    <td>{entry.get('port', '')}</td>
                    <td>{entry.get('service', '')}</td>
                    <td>{entry.get('url', '')}</td>
                    <td><span class="{color_cls}">{risk.upper()}</span></td>
                    <td>{entry.get('description', '')}</td>
                    <td class="suggestion">{entry.get('suggestion', '')}</td>
                </tr>"""

            risk_sum = self.risk_summary()
            risk_badge = ""
            if risk_sum.get("high"):
                risk_badge += f'<span class="badge-high">高危 {risk_sum["high"]}</span> '
            if risk_sum.get("medium"):
                risk_badge += f'<span class="badge-medium">中危 {risk_sum["medium"]}</span> '
            if risk_sum.get("low"):
                risk_badge += f'<span class="badge-low">低危 {risk_sum["low"]}</span> '
            if risk_sum.get("unknown"):
                risk_badge += f'<span class="badge-unknown">未知 {risk_sum["unknown"]}</span>'

            port_section = f"""
        <div class="section">
            <h2>📡 端口资产清单 — {self.port_inventory_host}</h2>
            <div class="summary-row">
                <span class="total">共发现 <strong>{len(self.port_inventory)}</strong> 个开放端口</span>
                {risk_badge}
            </div>
            <table>
            <thead>
                <tr>
                    <th>端口</th><th>服务</th><th>URL</th><th>风险等级</th><th>服务说明</th><th>收敛建议</th>
                </tr>
            </thead>
            <tbody>{port_rows}</tbody>
            </table>
        </div>"""
        else:
            port_section = ""

        # ── 漏洞发现部分 ───────────────────────────────────────────────────
        if self.results:
            vuln_rows = ""
            for r in self.results:
                severity = r.get("severity", "info")
                color_cls = {
                    "critical": "risk-high",
                    "high": "risk-high",
                    "medium": "risk-medium",
                    "low": "risk-low",
                    "info": "risk-info",
                }.get(severity, "risk-info")
                vuln_rows += f"""
                <tr>
                    <td>{r.get('target', '')}</td>
                    <td>{r.get('scanner', '')}</td>
                    <td>{r.get('title', '')}</td>
                    <td><span class="{color_cls}">{severity.upper()}</span></td>
                    <td>{r.get('url', '')}</td>
                    <td class="suggestion">{r.get('description', '')}</td>
                </tr>"""
            vuln_section = f"""
        <div class="section">
            <h2>🔓 漏洞检测结果</h2>
            <p>共发现风险点: <strong>{len(self.results)}</strong></p>
            <table>
            <thead>
                <tr>
                    <th>目标</th><th>模块</th><th>风险标题</th><th>严重程度</th><th>风险URL</th><th>描述</th>
                </tr>
            </thead>
            <tbody>{vuln_rows}</tbody>
            </table>
        </div>"""
        else:
            vuln_section = ""

        # ── 合并 HTML ──────────────────────────────────────────────────────
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>XSSCAN 暴露面扫描报告</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'PingFang SC','Microsoft YaHei',Arial,sans-serif;background:#0e1117;color:#e6edf3;padding:24px}}
h1{{color:#58a6ff;font-size:1.8em;margin-bottom:8px}} h2{{color:#8b949e;font-size:1.2em;margin:32px 0 12px;border-bottom:1px solid #21262d;padding-bottom:8px}}
.summary-row{{margin:12px 0;font-size:0.95em}}
.summary-row .total{{color:#8b949e}}
table{{width:100%;border-collapse:collapse;margin-top:8px;background:#161b22;border-radius:8px;overflow:hidden}}
th{{background:#1c2128;color:#8b949e;padding:10px 12px;text-align:left;font-size:0.85em;text-transform:uppercase;letter-spacing:0.05em;border-bottom:1px solid #30363d}}
td{{padding:9px 12px;border-bottom:1px solid #21262d;font-size:0.88em;vertical-align:top}}
tr:last-child td{{border-bottom:none}} tr:hover td{{background:#1c2128}}
.risk-high{{color:#f85149;font-weight:bold}} .risk-medium{{color:#d29922}} .risk-low{{color:#3fb950}} .risk-info{{color:#8b949e}}
.badge-high,.badge-medium,.badge-low,.badge-unknown{{display:inline-block;padding:2px 8px;border-radius:12px;font-size:0.78em;margin-left:8px}}
.badge-high{{background:rgba(248,81,73,0.15);color:#f85149}} .badge-medium{{background:rgba(210,153,34,0.15);color:#d29922}} .badge-low{{background:rgba(63,185,80,0.15);color:#3fb950}} .badge-unknown{{background:rgba(139,148,158,0.15);color:#8b949e}}
.suggestion{{max-width:360px;color:#8b949e;font-size:0.82em;line-height:1.5}}
.section{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;margin-bottom:20px}}
.section h2{{margin-top:0}}
p{{color:#8b949e;margin:8px 0}}
</style>
</head>
<body>
<h1>🛡️ XSSCAN 暴露面扫描报告</h1>
<p style="color:#8b949e;font-size:0.9em">生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; 工具版本: 1.1.0</p>
{port_section}
{vuln_section}
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    # ─── CSV ───────────────────────────────────────────────────────────────────

    def _save_csv(self, path):
        if self.port_inventory:
            fieldnames = ["host", "port", "service", "risk_level", "url", "description", "suggestion"]
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for entry in self.port_inventory:
                    row = {k: entry.get(k, "") for k in fieldnames}
                    writer.writerow(row)
