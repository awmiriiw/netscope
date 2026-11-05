import socket
import platform

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """ """

    CACHE_TTL: int = 3600
    WEB_SERVER_PORT: int = 8080
    NETWORK_INTERFACE: str = "auto"
    GRAPH_UPDATE_INTERVAL: int = 3000
    WEB_SERVER_HOST: str = "127.0.0.1"
    UPDATE_INTERVAL_SECONDS: int = 24 * 60 * 60

    BLOCKLIST_URL: str = (
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
    )

    @property
    def local_ip(self) -> str:
        """ """

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        try:
            s.connect(("8.8.8.8", 1))

            return s.getsockname()[0]

        except Exception:
            return "127.0.0.1"

        finally:
            s.close()

    def get_interface(self) -> str:
        """ """

        if self.NETWORK_INTERFACE != "auto":

            return self.NETWORK_INTERFACE

        system = platform.system().lower()

        if system == "windows":

            return "Ethernet"

        if system == "linux":

            return "any"

        if system == "darwin":

            return "en0"

        return "any"


setting = Settings()
