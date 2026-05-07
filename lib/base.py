#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
扫描器基类
所有中间件扫描器继承此基类
"""

from abc import ABC, abstractmethod


class BaseScanner(ABC):
    """
    扫描器基类
    子类只需实现 scan() 方法，返回风险点列表
    """

    # 严重程度常量
    SEV_HIGH   = "high"
    SEV_MEDIUM = "medium"
    SEV_LOW    = "low"
    SEV_INFO   = "info"

    def __init__(self, http_client):
        self.http = http_client

    @abstractmethod
    def scan(self, target):
        """
        扫描目标中间件
        参数:
            target: 形如 http://example.com:8848 的基础 URL
        返回:
            list[dict] 风险点列表，每项格式:
            {
                "target":    str,   # 扫描目标
                "url":       str,   # 风险 URL
                "title":     str,   # 风险标题
                "severity":  str,   # high | medium | low | info
                "description": str, # 风险描述
                "extra":     dict,  # 额外信息（可选）
            }
        """
        raise NotImplementedError

    def build_finding(self, target, url, title, severity, description, extra=None):
        """构造标准风险点字典"""
        return {
            "target":      target,
            "url":         url,
            "title":       title,
            "severity":    severity,
            "description": description,
            "extra":       extra or {},
        }
