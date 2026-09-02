import time
import requests
import threading

from requests import Response
from typing import Set, List, Optional
from ipaddress import ip_network, ip_address

from config.settings import setting
from utils.netscope_logger import RecordLog


class ThreatIntel:
    """ """

    def __init__(self) -> None:
        """ """

        self.last_updated = 0
        self.malicious_networks: List = []
        self.malicious_ips: Set[str] = set()

        self.lock = threading.RLock()
        self._updating_lock = threading.Lock()
        self._updating = False

        self.logger = RecordLog(__name__)

    def _fetch(self) -> Optional[Response]:
        """ """

        for attempt in range(3):
            try:
                response = requests.get(
                    setting.BLOCKLIST_URL,
                    timeout=15,
                )
                response.raise_for_status()

                return response

            except requests.RequestException as e:
                self.logger.warning(f"[THREAT] retry {attempt+1}: {e}")

                time.sleep(2 + attempt)

        return None

    def _download_list(self) -> None:
        """ """

        try:
            response = self._fetch()

            if not response:

                return

            new_ips: Set[str] = set()
            new_networks: List = []

            for line in response.text.splitlines():
                line = line.strip()

                if not line or line.startswith("#"):
                    continue

                try:
                    if "/" in line:
                        new_networks.append(ip_network(line, strict=False))

                    else:
                        new_ips.add(line)

                except ValueError:
                    continue

            with self.lock:
                self.malicious_ips = new_ips
                self.malicious_networks = new_networks
                self.last_updated = time.time()

            self.logger.info(
                f"[THREAT] updated: {len(new_ips)} IPs, {len(new_networks)} nets"
            )

        except Exception as e:
            self.logger.error(f"[THREAT] update failed: {e}", exc_info=True)

        finally:
            with self._updating_lock:
                self._updating = False

    def update_if_needed(self) -> None:
        """ """

        with self._updating_lock:
            if self._updating:

                return

            if time.time() - self.last_updated < setting.UPDATE_INTERVAL_SECONDS:

                return

            self._updating = True

        threading.Thread(
            target=self._download_list,
            daemon=True,
            name="ThreatIntelUpdater",
        ).start()

    def is_malicious(self, ip: str) -> bool:
        """ """

        try:
            ip_obj = ip_address(ip)

        except ValueError:

            return False

        with self.lock:
            if ip in self.malicious_ips:

                return True

            nets = list(self.malicious_networks)

        for net in nets:
            if ip_obj in net:

                return True

        return False


threat_intel_instance = ThreatIntel()
