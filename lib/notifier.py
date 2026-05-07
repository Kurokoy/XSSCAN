#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
企微机器人 Webhook 消息推送
支持 text 和 markdown 两种消息类型
"""

import json
import urllib.request
import urllib.error
from datetime import datetime


# 默认企微 webhook（可在初始化时覆盖）
DEFAULT_WEBHOOK = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=bb738ef2-3264-4844-9f11-f969948a2397"


class WeChatNotifier:
    """
    企微机器人 Webhook 推送器
    """

    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url or DEFAULT_WEBHOOK

    def send(self, msg_type, content):
        """
        发送消息到企微机器人
        msg_type: "text" | "markdown"
        content: 消息内容（dict，根据类型不同结构不同）
        """
        payload = {
            "msgtype": msg_type,
            msg_type: content
        }
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())
                if result.get("errcode") == 0:
                    return True, "发送成功"
                else:
                    return False, f"企微返回错误: {result.get('errmsg', result)}"
        except urllib.error.HTTPError as e:
            return False, f"HTTP错误: {e.code} {e.reason}"
        except urllib.error.URLError as e:
            return False, f"网络错误: {e.reason}"
        except Exception as e:
            return False, f"未知错误: {str(e)}"

    def send_text(self, content, mentioned_list=None):
        """
        发送纯文本消息
        content: 文本内容
        mentioned_list: 要 @ 的用户 user_id 列表（可选）
        """
        payload = {"content": content}
        if mentioned_list:
            payload["mentioned_list"] = mentioned_list
        return self.send("text", payload)

    def send_markdown(self, content):
        """
        发送 Markdown 消息
        content: Markdown 格式文本，支持以下语法:
          - # 标题
          - **加粗**
          - `code` 行内代码
          - > 引用
          - - 无序列表
          - 1. 有序列表
          - [链接](url)
        """
        return self.send("markdown", {"content": content})

    # ─── 扫描结果格式化 ────────────────────────────────────────────────────

    def format_scan_summary(self, results, port_inventory, target=None):
        """
        将扫描结果格式化为企微 Markdown 消息
        results: 漏洞检测结果列表
        port_inventory: 端口资产清单列表
        target: 扫描目标（可选）
        """
        lines = []

        # 标题
        lines.append("## 🛡️ XSSCAN 暴露面扫描报告")
        lines.append(f"**扫描时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if target:
            lines.append(f"**扫描目标**: `{target}`")

        # 风险统计
        vuln_count = len(results)
        port_count = len(port_inventory)
        high_risk = sum(1 for e in port_inventory if e.get("risk_level") == "high")
        medium_risk = sum(1 for e in port_inventory if e.get("risk_level") == "medium")

        lines.append("")
        lines.append("### 📊 风险统计")
        lines.append(f"- 漏洞检测结果: **{vuln_count}** 个")
        lines.append(f"- 开放端口: **{port_count}** 个")

        if port_inventory:
            risk_parts = []
            if high_risk > 0:
                risk_parts.append(f"🔴 高危 **{high_risk}** 个")
            if medium_risk > 0:
                risk_parts.append(f"🟡 中危 **{medium_risk}** 个")
            if risk_parts:
                lines.append(f"- 端口风险: {' | '.join(risk_parts)}")

        # 高危端口清单
        high_ports = [e for e in port_inventory if e.get("risk_level") == "high"]
        if high_ports:
            lines.append("")
            lines.append("### 🔴 高危端口（需立即处置）")
            for entry in high_ports[:10]:  # 最多显示10个
                lines.append(
                    f"- `{entry.get('port', '')}` "
                    f"{entry.get('service', '')} "
                    f"[{entry.get('url', '')}]({entry.get('url', '')})"
                )
            if len(high_ports) > 10:
                lines.append(f"> ...还有 **{len(high_ports) - 10}** 个高危端口，详见完整报告")

        # 中危端口
        medium_ports = [e for e in port_inventory if e.get("risk_level") == "medium"]
        if medium_ports:
            lines.append("")
            lines.append("### 🟡 中危端口（建议尽快处置）")
            for entry in medium_ports[:10]:
                lines.append(
                    f"- `{entry.get('port', '')}` "
                    f"{entry.get('service', '')} "
                    f"[{entry.get('url', '')}]({entry.get('url', '')})"
                )
            if len(medium_ports) > 10:
                lines.append(f"> ...还有 **{len(medium_ports) - 10}** 个中危端口，详见完整报告")

        # 漏洞发现
        if results:
            lines.append("")
            lines.append("### 🔓 漏洞检测结果")
            for r in results[:10]:
                severity = r.get("severity", "info")
                sev_emoji = {"critical": "🔴", "high": "🔴", "medium": "🟡", "low": "🟢"}.get(severity, "⚪")
                lines.append(
                    f"- {sev_emoji} **{r.get('title', '未知漏洞')}** "
                    f"({r.get('scanner', '')}) @ `{r.get('url', r.get('target', ''))}`"
                )
            if len(results) > 10:
                lines.append(f"> ...还有 **{len(results) - 10}** 个漏洞，详见完整报告")

        # 收敛建议
        if high_risk > 0:
            lines.append("")
            lines.append("> ⚠️ **请立即对上述高危端口进行收敛处置！**")

        return "\n".join(lines)

    def notify_scan_complete(self, results, port_inventory, target=None):
        """
        扫描完成后发送通知
        results: 漏洞检测结果列表
        port_inventory: 端口资产清单列表
        target: 扫描目标
        返回: (success, message)
        """
        content = self.format_scan_summary(results, port_inventory, target)
        return self.send_markdown(content)

    def notify_scan_start(self, target, mode="full"):
        """
        扫描开始时发送通知
        """
        content = (
            f"## 🚀 XSSCAN 扫描启动\n\n"
            f"**扫描目标**: `{target}`\n"
            f"**扫描模式**: {mode}\n"
            f"**开始时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"> 扫描进行中，稍后推送结果..."
        )
        return self.send_markdown(content)
