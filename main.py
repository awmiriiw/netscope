import sys
import threading

from web import app

from config.settings import setting
from capture.sniff_manager import Sniffer
from utils.netscope_logger import RecordLog
from graph.graph_manager import NetworkGraph
from threat.threat_intel_manager import threat_intel_instance

logger = RecordLog(__name__)


def main() -> None:
    """ """

    logger.info("Initializing Network Visualizer...")

    sniffer = None

    try:
        threat_intel_instance.update_if_needed()

        graph_manager = NetworkGraph(my_local_ip=setting.local_ip)

        interface = setting.get_interface()

        sniffer = Sniffer(
            network_graph=graph_manager,
            interface=interface,
        )

        logger.info("[BOOT] starting sniffer...")

        sniffer.start()

        threading.Event().wait(1)

        app.run_server(graph_manager, sniffer)

    except Exception as e:
        logger.critical(f"Failed to start the application: {e}", exc_info=True)

        sys.exit(1)

    finally:
        if sniffer:
            try:
                sniffer.stop()

            except Exception:
                pass


if __name__ == "__main__":
    main()
