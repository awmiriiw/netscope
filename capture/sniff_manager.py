import pyshark
import threading

from typing import Any, Optional
from queue import Queue, Full, Empty

from config.settings import setting
from utils.netscope_logger import RecordLog
from graph.graph_manager import ip_hostname_cache


class Sniffer:
    def __init__(
        self,
        network_graph: Any,
        interface: Optional[str] = None,
        queue_size: int = 5000,
        worker_count: int = 2,
    ) -> None:
        """ """

        self.worker_count = worker_count
        self.logger = RecordLog(__name__)
        self._running = threading.Event()
        self.network_graph = network_graph
        self.worker_threads: list[threading.Thread] = []
        self.capture: Optional[pyshark.LiveCapture] = None
        self.packet_queue: Queue = Queue(maxsize=queue_size)
        self.interface = interface or setting.get_interface()
        self.capture_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """ """

        if self._running.is_set():
            self.logger.warning("[START] already running")

            return

        self._running.set()

        self.logger.info(f"[START] Sniffer on interface: {self.interface}")

        self.capture_thread = threading.Thread(
            target=self._sniff_loop, daemon=True, name="CaptureThread"
        )
        self.capture_thread.start()
        self.worker_threads.clear()

        for i in range(self.worker_count):
            t = threading.Thread(
                target=self._worker_loop, daemon=True, name=f"Worker-{i}"
            )
            t.start()
            self.worker_threads.append(t)

        self.logger.info("[START] workers started")

    def stop(self) -> None:
        """ """

        self.logger.info("[STOP] stopping sniffer")

        self._running.clear()

        try:
            if self.capture:
                self.capture.close()

        except Exception:
            pass

        if self.capture_thread:
            self.capture_thread.join(timeout=5)

        for t in self.worker_threads:
            t.join(timeout=5)

        self.worker_threads.clear()

        self.logger.info("[STOP] stopped")

    def is_running(self) -> bool:
        """ """

        return self._running.is_set()

    def _sniff_loop(self) -> None:
        """ """

        try:
            self.logger.info(f"[CAPTURE] initializing on {self.interface}")

            self.capture = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter="ip",
            )

            self.logger.info("[CAPTURE] LiveCapture ready")

            for packet in self.capture.sniff_continuously():
                if not self._running.is_set():
                    break

                try:
                    self.packet_queue.put_nowait(packet)

                except Full:
                    try:
                        self.packet_queue.get_nowait()

                    except Empty:
                        pass

                    try:
                        self.packet_queue.put_nowait(packet)

                    except Full:
                        pass

        except Exception as e:
            self.logger.error(f"[CAPTURE] crash: {e}", exc_info=True)

        finally:
            self.logger.info("[CAPTURE] stopped")

    def _worker_loop(self) -> None:
        """ """

        self.logger.info(f"[WORKER] started {threading.current_thread().name}")

        while self._running.is_set() or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=0.5)

            except Empty:
                continue

            try:
                self._process_packet(packet)

            finally:
                self.packet_queue.task_done()

    def _process_packet(self, packet: Any) -> None:
        """ """

        try:
            try:
                if hasattr(packet, "dns"):
                    dns = packet.dns

                    if getattr(dns, "flags_response", "0") == "1":
                        domain = getattr(dns, "qry_name", None)

                        if hasattr(dns, "a") and domain:
                            ips = dns.a.split(",") if "," in dns.a else [dns.a]

                            for ip in ips:
                                ip = ip.strip()
                                ip_hostname_cache.set(
                                    ip, {"full": domain, "simple": domain}
                                )

                        if hasattr(dns, "aaaa") and domain:
                            ips = dns.aaaa.split(",") if "," in dns.aaaa else [dns.aaaa]

                            for ip in ips:
                                ip = ip.strip()
                                ip_hostname_cache.set(
                                    ip, {"full": domain, "simple": domain}
                                )

            except Exception:
                pass

            try:
                if hasattr(packet, "tls"):
                    sni = getattr(packet.tls, "handshake_extensions_server_name", None)

                    if sni and hasattr(packet, "ip"):
                        ip = packet.ip.dst
                        ip_hostname_cache.set(ip, {"full": sni, "simple": sni})

            except Exception:
                pass

            try:
                if hasattr(packet, "http"):
                    host = getattr(packet.http, "host", None)

                    if host and hasattr(packet, "ip"):
                        ip = packet.ip.dst
                        ip_hostname_cache.set(ip, {"full": host, "simple": host})

            except Exception:
                pass

            if not hasattr(packet, "ip"):

                return

            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            protocol = getattr(packet, "transport_layer", None)

            src_port = 0
            dst_port = 0

            if protocol:
                try:
                    layer = packet[protocol]
                    src_port = int(getattr(layer, "srcport", 0) or 0)
                    dst_port = int(getattr(layer, "dstport", 0) or 0)

                except Exception:
                    pass

            packet_size = int(getattr(packet, "length", 0))

            self.network_graph.add_connection(
                src_ip,
                dst_ip,
                protocol or "unknown",
                src_port,
                dst_port,
                packet_size,
            )

        except Exception as e:
            self.logger.error(f"[PROCESS] failed: {e}", exc_info=True)
