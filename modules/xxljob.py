#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XXL-Job 扫描器
检测未授权任务执行、任务管理面板等风险
"""

import json
from lib.base import BaseScanner


class XXLJobScanner(BaseScanner):

    DEFAULT_PORT = 8080

    PATHS = [
        # 管理界面
        ("/xxl-job-admin",                     "index",        "XXL-Job 管理界面"),
        ("/xxl-job/",                           "index",        "XXL-Job 根路径"),
        # API 端点
        ("/xxl-job-admin/jobinfo/pageList",     "job_list",     "XXL-Job 任务列表泄露"),
        ("/xxl-job-admin/joblog/pageList",       "log_list",     "XXL-Job 执行日志泄露"),
        ("/xxl-job-admin/jobgroup/pageList",     "group_list",    "XXL-Job 执行器列表泄露"),
        ("/xxl-job-admin/user/pageList",         "user_list",    "XXL-Job 用户列表"),
        ("/xxl-job-admin/api",                   "api",          "XXL-Job API 端点"),
        # 健康检查
        ("/xxl-job-admin/health",                "health",       "XXL-Job 健康检查"),
    ]

    def scan(self, target):
        findings = []
        base = target.rstrip("/")
        if not base:
            return findings

        for path, vuln_type, title in self.PATHS:
            url = f"{base}{path}"
            resp = self.http.get(url)
            if not self._is_valid(resp):
                continue

            content = self._safe_text(resp)
            severity, description = self._assess(vuln_type, content, resp.status_code)

            finding = self.build_finding(
                target=target,
                url=url,
                title=title,
                severity=severity,
                description=description,
                extra={"vuln_type": vuln_type, "status_code": resp.status_code}
            )
            findings.append(finding)
            print(f"  [{severity.upper():>6}] {title} -> {url}")

        return findings

    def _is_valid(self, resp):
        if resp is None:
            return False
        if resp.status_code == 404:
            return False
        return True

    def _safe_text(self, resp):
        try:
            return resp.text
        except Exception:
            return ""

    def _assess(self, vuln_type, content, status_code):
        if status_code == 200:
            if vuln_type in ("job_list", "log_list", "group_list", "user_list"):
                if self._contains_task_data(content):
                    return self.SEV_HIGH, "XXL-Job 任务/日志/用户列表泄露，攻击者可获取系统敏感信息并尝试执行恶意任务"
                return self.SEV_MEDIUM, "XXL-Job 敏感接口可访问"
            elif vuln_type == "index":
                if "xxl-job" in content.lower():
                    return self.SEV_MEDIUM, "XXL-Job 管理界面可访问，可能存在未授权操作风险"
                return self.SEV_LOW, "检测到 XXL-Job 相关页面"
            elif vuln_type == "api":
                return self.SEV_INFO, "XXL-Job API 端点开放"
            else:
                return self.SEV_LOW, f"XXL-Job {vuln_type} 接口可访问"
        elif status_code in (401, 403):
            return self.SEV_INFO, "XXL-Job 接口需要认证（未授权访问被拦截）"
        return self.SEV_INFO, f"XXL-Job 接口返回状态码 {status_code}"

    def _contains_task_data(self, content):
        """判断是否包含任务敏感数据"""
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                if data.get("code") == 200:
                    return True
                if "data" in data:
                    return True
        except Exception:
            pass
        return False
