#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端口扫描器 & 协议检测
对目标 IP/域名进行常见端口扫描，并检测 HTTP/HTTPS 协议
支持全端口扫描模式（扫描所有常见端口，不限于中间件）
"""

import socket
import concurrent.futures
import urllib.parse
from lib.http_client import HttpClient
from lib.service_db import COMMON_PORTS, get_port_info, build_port_report


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


# 防火墙/WAF 拦截特征状态码（不作为有效服务响应）
WAF_BLOCKED_CODES = {405, 501}

# 服务不可用状态码（端口通但服务挂了）
SERVICE_DOWN_CODES = {502, 503, 504}

# 所有需要过滤的状态码
FILTERED_CODES = WAF_BLOCKED_CODES | SERVICE_DOWN_CODES


def _is_valid_response(resp):
    """判断 HTTP 响应是否为有效服务响应（排除 WAF/防火墙拦截和服务不可用）"""
    if resp is None:
        return False
    try:
        return resp.status_code < 500 and resp.status_code not in FILTERED_CODES
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
        if _is_valid_response(resp):
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


def scan_all_ports(host, timeout=3, port_scan_timeout=3, max_workers=100):
    """
    全端口扫描：扫描 COMMON_PORTS 中定义的所有常见端口
    返回: list[int]  开放端口列表（已排序）
    """
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(scan_port, host, port, port_scan_timeout): port
            for port in COMMON_PORTS
        }
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass
    return sorted(open_ports)


def scan_all_ports_with_scheme(host, timeout=5, port_scan_timeout=3, max_workers=50):
    """
    全端口扫描 + 协议检测
    返回: (open_ports: list[int], schemes: dict[port -> scheme])
    """
    open_ports = scan_all_ports(host, timeout=timeout, port_scan_timeout=port_scan_timeout, max_workers=max_workers)

    if not open_ports:
        return [], {}

    # 对 HTTP 常用端口检测协议（跳过非 HTTP 端口避免浪费）
    http_candidate_ports = [p for p in open_ports if _is_http_port(p)]
    schemes = {}

    if not http_candidate_ports:
        # 没有 HTTP 候选端口，直接返回空 scheme 字典
        return open_ports, schemes

    waf_blocked_ports = set()
    http_unreachable_ports = set()
    service_down_ports = set()

    def try_scheme(port):
        """
        尝试 HTTP/HTTPS 探测，返回 (port, scheme, status)
        status: 'ok' = 有效响应, 'waf' = WAF 拦截(405/501), 
                'down' = 服务不可用(502/503/504), 'unreachable' = HTTP 不可达
        """
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}:{port}"
            try:
                resp = HttpClient(timeout=timeout).get(url)
                if resp is not None:
                    # 拿到了 HTTP 响应（任何状态码）
                    if resp.status_code in WAF_BLOCKED_CODES:
                        return port, scheme, "waf"
                    if resp.status_code in SERVICE_DOWN_CODES:
                        return port, scheme, "down"
                    return port, scheme, "ok"
                # resp is None = 请求失败（超时/连接拒绝/DNS错误等）
            except Exception:
                pass
        # 两种协议都无响应 = TCP 开放但 HTTP 不可达
        return port, "http", "unreachable"

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(http_candidate_ports), 30)) as executor:
        futures = {executor.submit(try_scheme, p): p for p in http_candidate_ports}
        for future in concurrent.futures.as_completed(futures):
            try:
                port, scheme, status = future.result()
                if status == "waf":
                    waf_blocked_ports.add(port)
                elif status == "down":
                    service_down_ports.add(port)
                elif status == "unreachable":
                    http_unreachable_ports.add(port)
                else:
                    schemes[port] = scheme
            except Exception:
                pass

    # 剔除 WAF/防火墙拦截的端口
    if waf_blocked_ports:
        print(f"[过滤] WAF 拦截端口 (405/501): {sorted(waf_blocked_ports)}")
        open_ports = [p for p in open_ports if p not in waf_blocked_ports]

    # 剔除服务不可用的端口（502/503/504）
    if service_down_ports:
        print(f"[过滤] 服务不可用端口 (502/503/504): {sorted(service_down_ports)}")
        open_ports = [p for p in open_ports if p not in service_down_ports]

    # 剔除 TCP 开放但 HTTP 不可达的端口（端口通但无 HTTP 服务）
    if http_unreachable_ports:
        print(f"[过滤] HTTP 不可达端口 (TCP 通但无 HTTP 响应): {sorted(http_unreachable_ports)}")
        open_ports = [p for p in open_ports if p not in http_unreachable_ports]

    return open_ports, schemes


def _is_http_port(port):
    """判断端口是否可能跑 HTTP 服务（用于跳过不必要的协议探测）"""
    # 常见非 HTTP 端口直接跳过
    non_http = {
        21, 22, 23, 25, 53, 67, 68, 69, 110, 111, 123, 135, 137, 138, 139,
        143, 161, 162, 389, 445, 465, 514, 515, 636, 993, 995,
        1433, 1434, 1521, 1723, 2049, 3306, 3389, 4369, 5432, 5666,
        5672, 5673, 5900, 5901, 5984, 6379, 6380, 7000, 7199, 8000,
        9200, 9300, 11211, 15672, 16379, 27017,
    }
    if port in non_http:
        return False
    return True


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
    host, _, _ = resolve_target_full(target)
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

    def full_scan(self, target):
        """
        全端口扫描模式：扫描所有常见端口，返回完整端口资产清单
        返回: list[dict]  每个元素 = {host, port, scheme, service, risk_level, url, description, suggestion}
        """
        target = target.strip()
        if not target:
            return []

        host, port, _ = resolve_target_full(target)
        if port:
            # 带端口的目标，直接返回单端口报告
            schemes = {}
            schemes[port] = detect_protocol(host, port, self.timeout)
            open_ports = [port]
        else:
            print(f"[全端口扫描] {host}，共 {len(COMMON_PORTS)} 个端口 ...\n")
            open_ports, schemes = scan_all_ports_with_scheme(
                host,
                timeout=self.timeout,
                port_scan_timeout=self.port_scan_timeout,
                max_workers=80,
            )

        if not open_ports:
            print(f"[无开放端口] {host}\n")
            return []

        # 构建完整报告（包含服务指纹 + 收敛建议）
        report = build_port_report(host, open_ports, schemes)

        # 对 HTTP 服务补全 module 字段（中间件匹配）
        middleware_port_to_module = {}
        for mod, ports in MIDDLEWARE_PORTS.items():
            for p in ports:
                middleware_port_to_module[p] = mod

        for entry in report:
            p = entry["port"]
            if p in middleware_port_to_module:
                entry["module"] = middleware_port_to_module[p]

        return report
