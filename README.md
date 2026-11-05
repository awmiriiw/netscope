# NetScope

NetScope is a real-time network traffic visualizer built with Python and Flask. It captures IP traffic from a selected network interface, maps observed connections into an interactive graph, and checks IP addresses against a FireHOL threat-intelligence blocklist.

## Overview

NetScope provides a local dashboard for viewing network activity, including:

- Live IPv4 packet capture and IP-to-IP connection mapping
- Interactive network graph with packet counts and estimated bandwidth
- DNS, TLS SNI, HTTP Host, and reverse-DNS hostname resolution
- Local-device and internet node classification
- Threat indicators based on the FireHOL Level 1 blocklist
- Dashboard controls for starting and stopping capture and clearing graph data
- Configurable capture interface, dashboard host and port, cache TTL, and blocklist URL

## Tech Stack

- Python
- Flask
- PyShark and TShark for packet capture
- NetworkX for the directed connection graph
- vis-network for browser-based graph visualization
- Pydantic Settings for environment-based configuration
- Requests for downloading threat-intelligence data

## Prerequisites

Before running the project, make sure you have:

- Python 3.10+
- pip
- TShark installed and available on your system
- Permission to capture packets on the selected network interface
- An internet connection for downloading the threat-intelligence blocklist and loading dashboard CDN assets

## Installation

1. Clone the repository and enter its directory.
2. Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows, activate it with:

```powershell
.venv\Scripts\activate
```

3. Install the listed dependencies and the two runtime packages currently missing from `requirements.txt`:

```bash
python -m pip install -r requirements.txt
```

4. Create your environment file:

```bash
cp .env.example .env
```

5. Start the application:

```bash
python main.py
```

Packet capture may require elevated privileges. On Linux or macOS, run the application with the permissions required by your TShark installation and selected interface.

Then open:

http://127.0.0.1:8080

## Environment Variables

The application reads these settings from `.env`:

```env
CACHE_TTL=3600
WEB_SERVER_PORT=8080
NETWORK_INTERFACE=auto
GRAPH_UPDATE_INTERVAL=3000
WEB_SERVER_HOST=127.0.0.1
UPDATE_INTERVAL_SECONDS=86400
BLOCKLIST_URL=https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset
```

### Variable Details

- `CACHE_TTL`: Lifetime, in seconds, for cached hostname and IP-related lookups.
- `WEB_SERVER_PORT`: Port used by the Flask dashboard. Defaults to `8080`.
- `NETWORK_INTERFACE`: Interface used for packet capture. `auto` selects a platform default: `any` on Linux, `en0` on macOS, or `Ethernet` on Windows.
- `GRAPH_UPDATE_INTERVAL`: Defined in the settings class, but currently not used by the application.
- `WEB_SERVER_HOST`: Address the dashboard binds to. Defaults to `127.0.0.1`, which keeps it accessible only from the local machine.
- `UPDATE_INTERVAL_SECONDS`: Minimum interval used by the threat-intelligence updater when deciding whether an update is due. The updater is started at application startup.
- `BLOCKLIST_URL`: URL of the FireHOL blocklist used to identify IPs and networks marked as malicious.

## Available Commands

```bash
python -m pip install -r requirements.txt
python main.py
```

The dashboard provides controls to start and stop packet capture and clear the graph data. The application also starts capture during startup.

## Notes

- TShark is an external system dependency; installing the Python packages alone is not sufficient for packet capture.
- Packet capture permissions depend on your operating system and TShark configuration.
- The dashboard uses external CDN assets for vis-network, Font Awesome, and Google Fonts.
- The Flask dashboard binds to `127.0.0.1` by default. The dashboard routes do not implement authentication, so do not expose it to untrusted networks without adding appropriate access controls.
- `requirements.txt` currently omits `pydantic-settings` and `coloredlogs`, both of which are imported by the application.
- Application logs are written to `logs/app.log`, with rotating backups.

## License

This project is licensed under the GNU Affero General Public License v3.0. See the [LICENSE](LICENSE) file for details.
