import sys
from web import app
from config import settings
from utils.logger import logger
from capture.sniffer import Sniffer
from core.network_graph import NetworkGraph
from utils.threat_intel import threat_intel_instance


def main():
    """Main entry point of the application."""
    
    logger.info("Initializing Network Visualizer...")

    threat_intel_instance.update_if_needed()
    graph_manager = NetworkGraph(my_local_ip=settings.MY_LOCAL_IP)
    sniffer = Sniffer(graph_manager, settings.NETWORK_INTERFACE)

    try:
        app.run_server(graph_manager, sniffer)
    except Exception as e:
        logger.critical(f"Failed to start the application: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()