import os
import socket
from dotenv import load_dotenv
from utils.logger import logger


def get_my_local_ip():
    """Retrieves the local machine's IP address."""
    
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = '127.0.0.1'
    finally:
        s.close()
    return ip_address

# ==================================
#     NETWORK SETTINGS
# ==================================
load_dotenv()

NETWORK_INTERFACE = os.getenv("NETWORK_INTERFACE")

if not NETWORK_INTERFACE:
    error_msg = "CRITICAL: NETWORK_INTERFACE not found in the .env file. The application cannot start."
    logger.critical(error_msg)
    raise ValueError(error_msg)

MY_LOCAL_IP = get_my_local_ip()
WEB_SERVER_HOST = "127.0.0.1"
WEB_SERVER_PORT = 8080

# ==================================
#     GRAPH SETTINGS
# ==================================
GRAPH_UPDATE_INTERVAL = 3000


logger.info("Configuration loaded successfully.")
