# NetScope

A high-performance, real-time network traffic analyzer and threat detection dashboard built with **Python**, **Flask**, **pyshark**, **networkx**, and **vis.js**.

Designed for security analysts and network engineers, it features live packet capture with multi-protocol deep inspection, dynamic force-directed network graph visualization, automated DNS/TLS/HTTP hostname resolution, FireHOL-based threat intelligence scoring, and a cyberpunk-styled command center web interface — all running locally with zero external dependencies beyond the blocklist feed.

---

## Key Features

### 🌐 Live Packet Capture & Analysis

- **Multi-Threaded Sniffer Engine:** High-throughput packet capture via `pyshark.LiveCapture` with configurable BPF filters, bounded packet queue, and parallel worker threads for non-blocking processing.
- **Protocol Deep Inspection:** Parses IP, TCP/UDP, DNS, TLS, and HTTP layers in real time to extract source/destination pairs, ports, packet sizes, and transport metadata.
- **Graceful Lifecycle Management:** Thread-safe start/stop controls with daemon threads, clean capture teardown, and queue drain on shutdown.

### 🔗 Network Graph Visualization

- **Directed Traffic Graph:** Builds and maintains a `networkx.DiGraph` of all observed IP-to-IP connections with cumulative packet counts and byte totals per edge.
- **Real-Time Force-Directed Rendering:** Interactive browser-based visualization powered by `vis.js` with `forceAtlas2Based` physics, curved directional arrows, and hover/click interactions.
- **Bandwidth Estimation:** Per-edge rolling traffic history (5,000-sample deque) with real-time KB/s bandwidth calculation over configurable time windows.
- **Node Classification:** Automatic categorization of nodes as `my_device`, `local_device`, or `internet` based on local IP detection and RFC 1918 private address ranges.

### 🛡️ Threat Intelligence & Malicious IP Detection

- **FireHOL Blocklist Integration:** Downloads and parses the `firehol_level1.netset` feed containing known malicious IPs and CIDR ranges.
- **Dual-Lookup Engine:** O(1) hash-set matching for individual IPs plus linear CIDR network containment checks via Python's `ipaddress` module.
- **Background Auto-Update:** Non-blocking periodic refresh (default: 24 hours) with retry logic, thread-safe list swapping, and deduplication.
- **Visual Threat Indicators:** Malicious nodes are highlighted in red across the graph, info panel, and search results in real time.

### 🏷️ Hostname & Protocol Resolution

- **DNS Response Parsing:** Extracts domain-to-IP mappings from DNS answer records (A and AAAA) for instant hostname labeling.
- **TLS SNI Extraction:** Reads the Server Name Indication from TLS Client Hello handshakes to identify HTTPS destinations.
- **HTTP Host Header Capture:** Falls back to HTTP `Host` headers for unencrypted traffic identification.
- **Async Reverse DNS:** ThreadPoolExecutor-powered `socket.gethostbyaddr()` lookups with TTL-cached results to avoid redundant queries.

### 📊 Cyberpunk Command Center Dashboard

- **Real-Time Status Feed:** Auto-refreshing (2.5s interval) node/edge data with live capture status indicator (LIVE_SCAN / IDLE).
- **Node Intelligence Panel:** Slide-out detail panel showing resolved IP, domain, and security threat status on click.
- **Interactive Search:** Instant client-side filtering across IP addresses and resolved domain names with golden highlight.
- **Capture Controls:** One-click START / STOP / PURGE_DATA buttons wired to backend Flask API endpoints.

### ⚙️ Configuration & Observability

- **Environment-Based Settings:** Full configuration via `pydantic-settings` with `.env` file support — interface, ports, cache TTL, blocklist URL, and update intervals.
- **Auto Interface Detection:** Platform-aware network interface selection (`any` on Linux, `en0` on macOS, `Ethernet` on Windows) with manual override.
- **Structured Logging:** Dual-output logging with `coloredlogs` console formatting and 10MB rotating file handlers with 5-file backup.
- **TTL Cache Layer:** Thread-safe in-memory caches with configurable expiration for hostname, IP info, and MAC vendor lookups.

---

## Get Start:

```
sudo pip3 install -r requirements.txt --break-system-packages

sudo python3 main.py
```

Then open your browser at:

```
http://127.0.0.1:8080
```

> **Hint:** Edit `./config/settings.py` or create a `.env` file in the project root to customize the network interface, web server port, cache TTL, and blocklist URL before running.

---

## Available Scripts

| Command                                 | Description                                               |
| :-------------------------------------- | :-------------------------------------------------------- |
| `sudo python3 main.py`                  | Starts the sniffer, threat intel updater, and web server. |
| `sudo pip3 install -r requirements.txt` | Installs all Python dependencies system-wide.             |
| `echo 'NETWORK_INTERFACE=eth0' > .env`  | Overrides the auto-detected capture interface.            |
| `echo 'WEB_SERVER_PORT=9090' >> .env`   | Changes the dashboard listening port.                     |
| `echo 'CACHE_TTL=7200' >> .env`         | Adjusts the hostname/IP cache expiration (seconds).       |

---

## License

This project is under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

See the [LICENSE](LICENSE) file for the complete license text.
