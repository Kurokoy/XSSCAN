#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nacos 扫描器
检测未授权访问、敏感配置泄露等风险
"""

import json
from lib.base import BaseScanner


class NacosScanner(BaseScanner):

    # Nacos 默认端口
    DEFAULT_PORT = 8848

    # 风险检测路径
    PATHS = [
        # 认证相关
        ("/nacos/v1/auth/users?pageNo=1&pageSize=100",  "user_list",   "Nacos 用户列表泄露"),
        ("/nacos/v1/console/state",                      "console",     "Nacos 控制台状态泄露"),
        # 配置相关
        ("/nacos/v1/cs/configs?dataId=&group=&pageNo=1&pageSize=100&appName=&config_tags=", "config_list", "Nacos 配置列表未授权访问"),
        ("/nacos/v1/cs/configs?dataId=application&group=DEFAULT_GROUP", "application_config", "Nacos application.yml 配置泄露"),
        # 健康检查
        ("/nacos/v1/ns/operator/metrics",                "metrics",     "Nacos 监控指标泄露"),
        ("/nacos/v1/ns/operator/health",                 "health",      "Nacos 健康检查"),
        # 集群信息
        ("/nacos/v1/ns/clusterNodes",                    "cluster",      "Nacos 集群节点信息"),
        ("/nacos/v1/ns/operator/sdks",                   "sdks",         "Nacos 客户端 SDK 信息"),
        # 版本
        ("/nacos/v1/console/health/readiness",           "readiness",    "Nacos 就绪检查"),
        ("/nacos/v1/console/health/liveness",            "liveness",     "Nacos 存活检查"),
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
        """评估风险严重程度"""
        if status_code == 200:
            # 有内容返回，进一步判断
            if vuln_type in ("user_list", "config_list", "application_config"):
                if self._contains_user_data(content):
                    return self.SEV_HIGH, "检测到 Nacos 用户列表或配置信息泄露，攻击者可获取敏感凭据或系统配置"
                return self.SEV_MEDIUM, "检测到 Nacos 敏感接口开放，可能泄露系统信息"
            elif vuln_type == "console":
                return self.SEV_INFO, "Nacos 控制台状态接口开放"
            elif vuln_type in ("metrics", "health", "cluster"):
                return self.SEV_LOW, f"Nacos {vuln_type} 接口开放，可能泄露集群架构信息"
            else:
                return self.SEV_LOW, f"Nacos {vuln_type} 接口可访问"

        elif status_code in (401, 403):
            return self.SEV_INFO, "Nacos 接口需要认证（未授权访问被拦截）"

        return self.SEV_INFO, f"Nacos 接口返回状态码 {status_code}"

    def _contains_user_data(self, content):
        """简单判断是否包含用户或配置敏感数据"""
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                # 用户列表特征
                if "users" in data or "pageItems" in data:
                    return True
                # 配置列表特征
                if "configs" in data or "data" in data:
                    # 有实际配置内容
                    if len(content) > 50:
                        return True
        except Exception:
            pass
        return False
