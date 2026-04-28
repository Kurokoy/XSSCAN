#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
检测引擎
负责加载模块、调度扫描、收集结果
"""

import importlib
import os


class Detector:

    # 模块名 -> 类名的映射（文件名遵循模块名）
    MODULE_CLASS_MAP = {
        "nacos":       "NacosScanner",
        "xxljob":      "XXLJobScanner",
        "springboot":  "SpringBootScanner",
        "druid":       "DruidScanner",
        "grafana":     "GrafanaScanner",
        "redis":       "RedisScanner",
        "jenkins":     "JenkinsScanner",
        "elasticsearch": "ElasticsearchScanner",
        "rabbitmq":    "RabbitMQScanner",
        "apollo":      "ApolloScanner",
    }

    def __init__(self, http_client, module_names, config):
        self.http = http_client
        self.module_names = module_names
        self.config = config
        self._scanners = self._load_scanners()

    def _load_scanners(self):
        """动态加载扫描模块"""
        scanners = {}
        for name in self.module_names:
            try:
                mod = importlib.import_module(f"modules.{name}")
                cls_name = self.MODULE_CLASS_MAP.get(name, name.title() + "Scanner")
                cls = getattr(mod, cls_name, None)
                if cls is None:
                    print(f"[警告] 模块 {name} 未找到类 {cls_name}，跳过")
                    continue
                scanners[name] = cls(self.http)
                print(f"[加载] {name:<16s} 扫描器")
            except Exception as e:
                print(f"[警告] 加载模块 {name} 失败: {e}")
        return scanners

    def scan(self, target):
        """
        对单个目标执行所有已加载模块的扫描
        返回: list[dict]  每个风险点一条记录
        """
        results = []
        for name, scanner in self._scanners.items():
            try:
                findings = scanner.scan(target)
                if findings:
                    for f in findings:
                        f["scanner"] = name
                    results.extend(findings)
            except Exception as e:
                print(f"[错误] 扫描器 {name} 执行异常: {e}")
        return results
