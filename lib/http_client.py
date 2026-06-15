#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP 客户端封装
提供统一的请求接口，自动处理 redirects、超时、UA
"""

import requests
from urllib.parse import urlparse


class HttpClient:

    def __init__(self, timeout=10, user_agent=None, follow_redirects=True):
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.session = requests.Session()
        self.session.trust_env = False  # 不读取系统代理，避免 Windows 代理导致超时
        default_ua = "Mozilla/5.0 (compatible; XSSCAN/1.0; Linux) AppleWebKit/537.36"
        self.session.headers.update({
            "User-Agent": user_agent or default_ua,
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })

    def get(self, url, **kwargs):
        """发送 GET 请求"""
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", self.follow_redirects)
        kwargs.setdefault("verify", False)
        try:
            return self.session.get(url, **kwargs)
        except requests.exceptions.RequestException:
            return None

    def post(self, url, **kwargs):
        """发送 POST 请求"""
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", self.follow_redirects)
        kwargs.setdefault("verify", False)
        try:
            return self.session.post(url, **kwargs)
        except requests.exceptions.RequestException:
            return None

    def head(self, url, **kwargs):
        """发送 HEAD 请求"""
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", False)
        kwargs.setdefault("verify", False)
        try:
            return self.session.head(url, **kwargs)
        except requests.exceptions.RequestException:
            return None

    @staticmethod
    def is_alive(response):
        """判断响应是否有效（仅接受 2xx/3xx，>= 400 全部过滤）"""
        if response is None:
            return False
        try:
            return response.status_code < 400
        except Exception:
            return False

    @staticmethod
    def parse_url(base_url):
        """解析 URL，返回 scheme, host, port"""
        parsed = urlparse(base_url)
        scheme = parsed.scheme or "http"
        host = parsed.netloc or parsed.hostname or ""
        port = parsed.port
        return scheme, host, port
