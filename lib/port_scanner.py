#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端口扫描器 & 协议检测
对目标 IP/域名进行常见端口扫描，并检测 HTTP/HTTPS 协议
"""

import socket
import concurrent.futures
import urllib.parse
from lib.http_client import HttpClient


# 中间件默认端口表（模块名 -> 默认端口列表）
MIDDLEWARE_PORTS = {
    "nacos":        [8848, 8847, 8080],
    "xxljob":       [8080, 8090, 9000],
    "springboot":   [8080, 8090, 8000, 8443],
    "druid":        [8090, 8081, 9000],
    "grafana":      [3000, 8080],
    "redis":        [6379, 16379, 6380],
    "jenkins":      [8080, 8090, 8000],
    "elasticsearch": [9200, 9300, 9243],
    "rabbitmq":     [15672, 15692, 5672],
    "apollo":       [8070, 8090, 8080],
}


def scan_port(host, port, timeout=3):
    """检测单个端口是否开放"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def detect_protocol(host, port, timeout=5):
    """
    检测协议：同时发 HTTP 和 HTTPS 请求，
    返回先拿到有效响应的那个（http / https / None）
    """
    http_client = HttpClient(timeout=timeout)

    # 快速检测 SSL
    is_https = _is_ssl(port)

    def try_protocol(scheme):
        url = f"{scheme}://{host}:{port}"
        resp = http_client.get(url)
        if resp and resp.status_code < 500:
            return scheme
        return None

    # 并发探测
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        http_future = executor.submit(try_protocol, "http")
        https_future = executor.submit(try_protocol, "https")

        for future in concurrent.futures.as_completed(
            [http_future, https_future], timeout=timeout + 1
        ):
            try:
                result = future.result()
                if result:
                    return result
            except Exception:
                pass

    # 都失败了，按默认 SSL 端口判断
    return "https" if is_https else "http"


def _is_ssl(port):
    """常见 HTTPS 端口"""
    return port in (443, 8443, 9243, 15692, 15672)


def resolve_host(target):
    """
    将用户输入解析为 (host, scheme)
    支持: 1.2.3.4 / example.com / http://1.2.3.4 / https://example.com:8080
    返回: (host, None)  scheme 留空由 detect_protocol 填充
    """
    target = target.strip()
    if not target:
        return None, None

    # 去除协议
    if target.startswith("http://"):
        target = target[7:]
    elif target.startswith("https://"):
        target = target[8:]

    # 去除路径
    if "/" in target:
        target = target.split("/")[0]

    # 去除端口
    if ":" in target:
        host = target.rsplit(":", 1)[0]
    else:
        host = target

    return host, None


def scan_target(target, modules, timeout=3, port_scan_timeout=3):
    """
    扫描单个目标的所有模块端口
    返回: list[dict]  每个元素 = {host, port, scheme, module, url}
    """
    host, _ = resolve_target_full(target)
    if not host:
        return []

    results = []
    ports_to_check = set()

    # 收集需要扫描的端口
    for mod in modules:
        if mod in MIDDLEWARE_PORTS:
            for port in MIDDLEWARE_PORTS[mod]:
                ports_to_check.add(port)

    # 并发端口扫描
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(scan_port, host, port, port_scan_timeout): port
            for port in ports_to_check
        }
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass

    # 对每个开放端口检测协议
    for port in sorted(open_ports):
        scheme = detect_protocol(host, port, timeout)
        for mod in modules:
            if port in MIDDLEWARE_PORTS.get(mod, []):
                url = f"{scheme}://{host}:{port}"
                results.append({
                    "host": host,
                    "port": port,
                    "scheme": scheme,
                    "module": mod,
                    "url": url,
                    "target": f"{scheme}://{host}:{port}",
                })
                break  # 一个端口只匹配一个模块（按定义顺序优先）

    return results


def resolve_target_full(target):
    """
    完整解析用户输入
    返回: (host, port, scheme)
    """
    target = target.strip()
    scheme = None
    port = None

    # 提取 scheme
    if target.startswith("http://"):
        scheme = "http"
        target = target[7:]
    elif target.startswith("https://"):
        scheme = "https"
        target = target[8:]

    # 提取端口
    if ":" in target:
        parts = target.rsplit(":", 1)
        host = parts[0]
        if len(parts) == 2 and parts[1].isdigit():
            port = int(parts[1])
            target = host
    else:
        # 纯域名/IP，去掉路径
        target = target.split("/")[0]
        host = target

    return host, port, scheme


class PortScanner:

    def __init__(self, modules, config=None):
        self.modules = modules
        self.config = config or {}
        self.timeout = self.config.get("timeout", 5)
        self.port_scan_timeout = self.config.get("port_scan_timeout", 3)

    def scan(self, target):
        """
        扫描入口，同时支持:
        - 纯 IP / 域名（无端口） -> 端口扫描 + 协议检测
        - 带端口 URL（http://1.2.3.4:8848） -> 直接协议检测
        返回: list[dict]  扫描目标列表
        """
        target = target.strip()
        if not target:
            return []

        host, port, scheme = resolve_target_full(target)

        # 情况1: 带端口的完整 URL -> 跳过端口扫描
        if port:
            scheme = scheme or detect_protocol(host, port, self.timeout)
            result = {
                "host": host,
                "port": port,
                "scheme": scheme,
                "module": None,  # 由 detector 层匹配模块
                "url": f"{scheme}://{host}:{port}",
                "target": f"{scheme}://{host}:{port}",
            }
            return [result]

        # 情况2: 纯 IP / 域名 -> 端口扫描 + 协议检测
        return scan_target(
            target, self.modules,
            timeout=self.timeout,
            port_scan_timeout=self.port_scan_timeout
        )
