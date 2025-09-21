import pyshark
import threading
from utils.logger import logger


class Sniffer:
    """Handles live packet capturing and updates the network graph."""
    
    def __init__(self, network_graph, interface):
        """Initializes the sniffer with graph reference and interface."""
        
        self.network_graph = network_graph
        self.interface = interface
        self.capture_thread = None
        self.capture = None 
        self.is_running_flag = False

    def start(self):
        """Starts the packet capture in a non-blocking way."""
        
        if self.is_running_flag:
            logger.warning("Sniffer is already running.")
            return

        self.is_running_flag = True
        self.capture_thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.capture_thread.start()
        logger.info("Sniffer thread started.")

    def _sniff_loop(self):
        """The main loop for processing packets."""
        
        try:
            logger.info(f"Attempting to start packet capture on interface: {self.interface}")
            self.capture = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter="ip and (tcp or udp)"
            )
            
            logger.info("Packet capture started successfully. Listening for packets...")
            for packet in self.capture.sniff_continuously():
                logger.debug(f"Packet received: {packet.layers}")

                if not self.is_running_flag:
                    break
                
                src_mac = None
                dst_mac = None
                if hasattr(packet, 'eth'):
                    src_mac = packet.eth.src
                    dst_mac = packet.eth.dst

                if 'IP' in packet and hasattr(packet, 'transport_layer'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    protocol = packet.transport_layer
                    src_port = packet[protocol].srcport
                    dst_port = packet[protocol].dstport
                    packet_size = int(packet.length)

                    self.network_graph.add_connection(
                        src_ip, dst_ip,
                        protocol, src_port, dst_port,
                        packet_size, src_mac, dst_mac
                    )
        except Exception as e:
            logger.error(f"FATAL ERROR during packet capture setup or loop: {e}")
            logger.error("Please ensure Tshark is installed and in your system's PATH.")
            logger.error("Also, make sure you are running the script with sufficient privileges (sudo).")
        finally:
            if self.capture:
                self.capture.close()
            self.is_running_flag = False
            logger.info("Packet capture loop terminated.")

    def stop(self):
        """Signals the sniffer to stop capturing packets."""
        
        if not self.is_running_flag:
            logger.warning("Sniffer is not running.")
            return
        
        logger.info("Stopping packet capture...")
        self.is_running_flag = False
        if self.capture:
            self.capture.close()
            self.capture = None
    
    def is_running(self):
        """Checks if the sniffer is currently active."""
        
        return self.is_running_flag