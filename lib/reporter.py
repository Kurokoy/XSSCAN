#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
报告生成器
支持 JSON / HTML / CSV 格式输出
"""

import json
import csv
import os
from datetime import datetime


class Reporter:

    def __init__(self):
        self.results = []   # list[dict]
        self.target_map = {}  # target -> list[dict]

    def add_results(self, target, findings):
        """记录扫描结果"""
        self.results.extend(findings)
        self.target_map[target] = findings

    def total_findings(self):
        return len(self.results)

    def save(self, path, format="json"):
        """保存报告"""
        if format == "json":
            self._save_json(path)
        elif format == "html":
            self._save_html(path)
        elif format == "csv":
            self._save_csv(path)

    def _save_json(self, path):
        report = {
            "tool": "XSSCAN",
            "version": "1.0.0",
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(self.results),
            "results": self.results,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)

    def _save_html(self, path):
        rows = ""
        for r in self.results:
            rows += f"""
            <tr>
                <td>{r.get('target', '')}</td>
                <td>{r.get('scanner', '')}</td>
                <td>{r.get('title', '')}</td>
                <td><span class="severity-{r.get('severity', 'info')}">{r.get('severity', 'info')}</span></td>
                <td>{r.get('url', '')}</td>
                <td><pre>{r.get('description', '')}</pre></td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>XSSCAN Report</title>
<style>
body{{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5}}
h1{{color:#333}} table{{width:100%;border-collapse:collapse;background:#fff}}
th{{background:#2c3e50;color:#fff;padding:10px;text-align:left}}
td{{padding:8px;border-bottom:1px solid #ddd}} tr:hover{{background:#f9f9f9}}
.severity-high{{color:#e74c3c;font-weight:bold}} .severity-medium{{color:#f39c12}} .severity-low{{color:#3498db}} .severity-info{{color:#95a5a6}}
</style>
</head>
<body>
<h1>XSSCAN 暴露面扫描报告</h1>
<p>生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; 共发现风险点: <strong>{len(self.results)}</strong></p>
<table>
<tr><th>目标</th><th>模块</th><th>风险标题</th><th>严重程度</th><th>风险URL</th><th>描述</th></tr>
{rows}
</table>
</body>
</html>"""
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)

    def _save_csv(self, path):
        if not self.results:
            return
        fieldnames = list(self.results[0].keys())
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(self.results)
