import time
import socket
import threading

import networkx as nx
from typing import Any, Dict, List
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from ipaddress import ip_address, AddressValueError

from config.settings import setting
from utils.netscope_logger import RecordLog
from threat.threat_intel_manager import threat_intel_instance


def is_public_ip(ip: str) -> bool:
    """ """

    try:

        return not ip_address(ip).is_private

    except AddressValueError:

        return True


class TTLCache:
    """ """

    def __init__(self) -> None:
        """ """

        self._data = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        """ """

        with self._lock:
            item = self._data.get(key)

            if item is None:

                return None

            if time.time() - item["ts"] > setting.CACHE_TTL:
                self._data.pop(key, None)

                return None

            return item["value"]

    def set(self, key: str, value: Any) -> None:
        """ """

        with self._lock:
            self._data[key] = {"value": value, "ts": time.time()}


ip_info_cache = TTLCache()
ip_hostname_cache = TTLCache()
mac_vendor_cache = TTLCache()


class NetworkGraph:
    """ """

    def __init__(self, my_local_ip: str) -> None:
        """ """
        self.mac_map = {}
        self.graph = nx.DiGraph()
        self.lock = threading.Lock()
        self.my_local_ip = my_local_ip
        self.logger = RecordLog(__name__)
        self.resolver_pool = ThreadPoolExecutor(max_workers=10)
        self.edge_traffic_history = defaultdict(lambda: deque(maxlen=5000))

    def add_connection(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: int,
        dst_port: int,
        packet_size: int,
        src_mac: str | None = None,
        dst_mac: str | None = None,
    ) -> None:
        """ """

        try:
            current_time = time.time()

            src_malicious = threat_intel_instance.is_malicious(src_ip)
            dst_malicious = threat_intel_instance.is_malicious(dst_ip)

            with self.lock:
                if not self.graph.has_node(src_ip):
                    self.graph.add_node(src_ip)

                if not self.graph.has_node(dst_ip):
                    self.graph.add_node(dst_ip)

                self.graph.nodes[src_ip]["is_malicious"] = src_malicious
                self.graph.nodes[dst_ip]["is_malicious"] = dst_malicious

                if not self.graph.has_edge(src_ip, dst_ip):
                    self.graph.add_edge(src_ip, dst_ip, weight=0, total_size=0)

                edge = self.graph[src_ip][dst_ip]

                edge["weight"] += 1
                edge["total_size"] += packet_size

                self.edge_traffic_history[(src_ip, dst_ip)].append(
                    (current_time, packet_size)
                )

                self.resolver_pool.submit(self._resolve_async, src_ip, dst_ip)

        except Exception as e:
            self.logger.error(f"[GRAPH ERROR] {e}", exc_info=True)

    def _resolve_async(self, src_ip: str, dst_ip: str) -> None:
        """ """

        try:
            for ip in (src_ip, dst_ip):
                if ip_hostname_cache.get(ip) is None:
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]

                        ip_hostname_cache.set(
                            ip,
                            {
                                "full": hostname,
                                "simple": (
                                    hostname.split(".")[-2]
                                    + "."
                                    + hostname.split(".")[-1]
                                    if "." in hostname
                                    else hostname
                                ),
                            },
                        )

                    except (socket.herror, socket.gaierror):
                        ip_hostname_cache.set(ip, {"full": ip, "simple": ip})

        except Exception:
            pass

    def _get_node_type(self, ip: str) -> str:
        """ """

        if ip == self.my_local_ip:

            return "my_device"

        if not is_public_ip(ip):

            return "local_device"

        return "internet"

    def _calculate_bandwidth(self, src: str, dst: str, period_sec: int = 10) -> float:
        """ """

        history = self.edge_traffic_history.get((src, dst), deque())
        now = time.time()

        total = 0
        for ts, size in history:
            if now - ts <= period_sec:
                total += size

        return total / period_sec if period_sec else 0

    def get_graph_data(self) -> Dict[str, List[Dict[str, Any]]]:
        """ """

        nodes = []
        edges = []

        with self.lock:
            node_list = list(self.graph.nodes())
            edge_list = list(self.graph.edges(data=True))

        for node_ip in node_list:

            cache = ip_hostname_cache.get(node_ip) or {
                "full": node_ip,
                "simple": node_ip,
            }

            is_malicious = threat_intel_instance.is_malicious(node_ip)

            nodes.append(
                {
                    "id": node_ip,
                    "label": cache["simple"],
                    "title": f"IP: {node_ip}\nHost: {cache['full']}",
                    "node_type": self._get_node_type(node_ip),
                    "is_malicious": is_malicious,
                }
            )

        for u, v, data in edge_list:

            bw = self._calculate_bandwidth(u, v)

            edges.append(
                {
                    "from": u,
                    "to": v,
                    "value": data.get("weight", 0),
                    "title": (
                        f"Packets: {data.get('weight', 0)}\n"
                        f"Data: {data.get('total_size', 0) / 1024:.2f} KB\n"
                        f"BW: {bw / 1024:.2f} KB/s"
                    ),
                }
            )

        return {"nodes": nodes, "edges": edges}

    def clear(self) -> None:
        """ """

        with self.lock:
            self.graph.clear()
            self.edge_traffic_history.clear()
            self.mac_map.clear()
