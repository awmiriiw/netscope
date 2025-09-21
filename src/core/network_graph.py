import time
import asyncio
import threading
import tldextract 
import networkx as nx
from ipwhois import IPWhois
from utils.logger import logger
from collections import defaultdict
from dns import reversename, resolver
from utils.services import get_service_name
from mac_vendor_lookup import AsyncMacLookup
from ipwhois.exceptions import IPDefinedError
from ipaddress import ip_address, AddressValueError
from utils.threat_intel import threat_intel_instance


ip_hostname_cache = {}
ip_info_cache = {}
mac_vendor_cache = {}
mac_lookup = AsyncMacLookup()

def is_public_ip(ip):
    """Checks if an IP is public using the ipaddress module."""
    
    try:
        return not ip_address(ip).is_private
    except AddressValueError:
        return True

def resolve_background_tasks(ip, mac):
    """Runs DNS, WHOIS, and MAC vendor lookups for an IP/MAC in the background."""
    
    if ip not in ip_hostname_cache:
        try:
            full_hostname = ip
            simple_name = ip
            if is_public_ip(ip):
                addr = reversename.from_address(ip)
                full_hostname = str(resolver.resolve(addr, "PTR")[0]).rstrip('.')
                
                extracted = tldextract.extract(full_hostname)
                if extracted.domain and extracted.suffix:
                    simple_name = f"{extracted.domain}.{extracted.suffix}"
                else:
                    simple_name = full_hostname
            ip_hostname_cache[ip] = {'full': full_hostname, 'simple': simple_name}
        except Exception:
            ip_hostname_cache[ip] = {'full': ip, 'simple': ip}

    if ip not in ip_info_cache and is_public_ip(ip):
        is_malicious = threat_intel_instance.is_malicious(ip)
        info = {'is_malicious': is_malicious}
        try:
            obj = IPWhois(ip)
            results = obj.lookup_whois()
            info['whois'] = {'asn_description': results.get('asn_description', 'N/A')}
        except Exception:
            info['whois'] = None
        ip_info_cache[ip] = info

    if mac and mac not in mac_vendor_cache and not is_public_ip(ip):
        try:
            vendor = asyncio.run(mac_lookup.lookup(mac))
            mac_vendor_cache[mac] = vendor
        except Exception as e:
            logger.warning(f"MAC vendor lookup failed for {mac}: {e}")
            mac_vendor_cache[mac] = "Unknown Vendor"


class NetworkGraph:
    """Represents and manages the network traffic graph with nodes and edges."""
    
    def __init__(self, my_local_ip):
        """Initializes the graph structure and caches for traffic analysis."""
    
        self.graph = nx.DiGraph()
        self.lock = threading.Lock()
        self.my_local_ip = my_local_ip
        self.edge_traffic_history = defaultdict(list)
        self.mac_map = {}

    def add_connection(self, src_ip, dst_ip, protocol, src_port, dst_port, packet_size, src_mac=None, dst_mac=None):
        """Adds or updates a connection edge in the network graph."""
    
        with self.lock:
            if src_mac and not is_public_ip(src_ip):
                self.mac_map[src_ip] = src_mac
            if dst_mac and not is_public_ip(dst_ip):
                self.mac_map[dst_ip] = dst_mac
            if not self.graph.has_edge(src_ip, dst_ip):
                self.graph.add_edge(src_ip, dst_ip, weight=0, total_size=0, protocols=defaultdict(int))
            
            self.graph[src_ip][dst_ip]['weight'] += 1
            self.graph[src_ip][dst_ip]['total_size'] += packet_size
            service = get_service_name(int(dst_port))
            port_info = f"{protocol.upper()}:{service}"
            self.graph[src_ip][dst_ip]['protocols'][port_info] += 1
            
            current_time = time.time()
            history = self.edge_traffic_history[(src_ip, dst_ip)]
            history.append((current_time, packet_size))
            self.edge_traffic_history[(src_ip, dst_ip)] = [t for t in history if current_time - t[0] <= 60]

        for ip, mac in [(src_ip, src_mac), (dst_ip, dst_mac)]:
            if ip not in ip_hostname_cache or (mac and mac not in mac_vendor_cache):
                threading.Thread(target=resolve_background_tasks, args=(ip, mac), daemon=True).start()

    def _get_node_type(self, ip):
        """Determines the type of a node (local, my device, internet)."""
        
        if ip == self.my_local_ip: return "my_device"
        if not is_public_ip(ip): return "local_device"
        return "internet"

    def _calculate_bandwidth(self, src, dst, period_sec=10):
        """Calculates bandwidth in bytes per second."""
        
        current_time = time.time()
        history = self.edge_traffic_history.get((src, dst), [])
        total_bytes = sum(size for ts, size in history if current_time - ts <= period_sec)
        return total_bytes / period_sec if period_sec > 0 else 0

    def get_graph_data(self):
        """Generates graph data for the frontend."""
        
        with self.lock:
            nodes = []
            for node_ip in self.graph.nodes():
                node_names = ip_hostname_cache.get(node_ip, {'full': node_ip, 'simple': node_ip})
                simple_name = node_names.get('simple', node_ip)
                full_name = node_names.get('full', node_ip)
                
                node_type = self._get_node_type(node_ip)
                is_malicious = ip_info_cache.get(node_ip, {}).get('is_malicious', False)
                nodes.append({
                    'id': node_ip,
                    'label': simple_name, 
                    'title': f"IP: {node_ip}\nHost: {full_name}",
                    'node_type': node_type,
                    'is_malicious': is_malicious
                })
            
            edges = []
            for u, v, data in self.graph.edges(data=True):
                total_size_kb = data.get('total_size', 0) / 1024
                bandwidth_kbps = self._calculate_bandwidth(u, v) / 1024
                title = (f"Packets: {data.get('weight', 0)}\n"
                         f"Data: {total_size_kb:.2f} KB\n"
                         f"BW: {bandwidth_kbps:.2f} KB/s")
                edges.append({'from': u, 'to': v, 'value': data.get('weight', 0), 'title': title})

            return {'nodes': nodes, 'edges': edges}

    def get_node_info(self, node_id):
        """Retrieves detailed information for a specific node."""
        
        with self.lock:
            if not self.graph.has_node(node_id): return None
            
            full_hostname = ip_hostname_cache.get(node_id, {}).get('full', "Resolving...")
            info = {"ip": node_id, "hostname": full_hostname}
            node_type = self._get_node_type(node_id)
            
            details = {}
            if node_type == 'local_device' or node_type == 'my_device':
                mac = self.mac_map.get(node_id)
                if mac:
                    details['mac_address'] = mac
                    details['vendor'] = mac_vendor_cache.get(mac, "Looking up...")
            elif node_type == 'internet':
                ip_info = ip_info_cache.get(node_id)
                if ip_info:
                    details['is_malicious'] = ip_info.get('is_malicious', False)
                    if ip_info.get('whois'):
                        details['owner'] = ip_info['whois'].get('asn_description', 'N/A')
            info['details'] = details

            incoming_details = []
            for u, _, data in self.graph.in_edges(node_id, data=True):
                incoming_details.append({
                    "from": u, "from_host": ip_hostname_cache.get(u, {}).get('simple', u),
                    "weight": data.get('weight', 0),
                    "total_size": data.get('total_size', 0),
                    "protocols": dict(data.get('protocols', {}))
                })
            info['incoming_details'] = incoming_details

            outgoing_details = []
            for _, v, data in self.graph.out_edges(node_id, data=True):
                outgoing_details.append({
                    "to": v, "to_host": ip_hostname_cache.get(v, {}).get('simple', v),
                    "weight": data.get('weight', 0),
                    "total_size": data.get('total_size', 0),
                    "protocols": dict(data.get('protocols', {}))
                })
            info['outgoing_details'] = outgoing_details
            
            return info

    def clear(self):
        """Clears all graph data."""
        
        with self.lock:
            self.graph.clear()
            self.edge_traffic_history.clear()
            logger.info("Network graph data has been cleared.")