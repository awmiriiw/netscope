import time
import requests
import threading
from utils.logger import logger

BLOCKLIST_URL = "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
UPDATE_INTERVAL_SECONDS = 24 * 60 * 60


class ThreatIntel:
    """Handles downloading and checking of malicious IP blocklists."""
    
    def __init__(self):
        """Initializes threat intelligence storage and state."""
        
        self.malicious_ips = set()
        self.lock = threading.Lock()
        self.last_updated = 0

    def _download_list(self):
        """Downloads the blocklist and updates the internal set."""
        
        logger.info("Attempting to download threat intelligence blocklist...")
        try:
            response = requests.get(BLOCKLIST_URL, timeout=20)
            response.raise_for_status()  
            
            new_ips = set()
            lines = response.text.splitlines()
            for line in lines:
                if not line.strip().startswith('#') and line.strip():
                    new_ips.add(line.strip())
            
            with self.lock:
                self.malicious_ips = new_ips
                self.last_updated = time.time()
            logger.info(f"Threat intelligence list updated successfully. Found {len(new_ips)} malicious IPs.")
        
        except requests.RequestException as e:
            logger.error(f"Failed to download threat intelligence list: {e}")

    def update_if_needed(self):
        """Checks if an update is needed and runs it in a background thread."""

        if time.time() - self.last_updated > UPDATE_INTERVAL_SECONDS:
            update_thread = threading.Thread(target=self._download_list, daemon=True)
            update_thread.start()

    def is_malicious(self, ip):
        """Checks if an IP is in the malicious list."""

        with self.lock:
            return ip in self.malicious_ips


threat_intel_instance = ThreatIntel()