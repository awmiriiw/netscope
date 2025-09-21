# Netscope

NetScope is an advanced, real-time network traffic visualizer that captures and maps your system's network connections into a beautiful and interactive graph. It provides deep insights into your network activity through a clean web-based dashboard.

## 🔎 About

Understanding what's happening on your network can be challenging. Traditional tools like `tcpdump` or `wireshark` are incredibly powerful but often present data in a format that is difficult to interpret at a glance. It's hard to quickly see who is talking to whom, what services are being used, and if any suspicious connections exist.

NetScope was built to solve this problem. It runs a lightweight packet sniffer in the background, processes the traffic in real-time, and renders it as an intuitive graph of nodes (devices) and edges (connections). The data is automatically enriched with valuable context like hostnames, MAC address vendors, WHOIS information, and even threat intelligence data to flag potentially malicious IPs.

This tool is perfect for network administrators, security enthusiasts, developers debugging network applications, or anyone curious about their digital connections.

## 🛠️ Features

- **Live Traffic Visualization**: Renders network connections in real-time as an interactive and dynamic graph using `vis.js`.
- **Detailed Packet Analysis**: Captures IP, port, protocol, and packet size for both TCP and UDP traffic to provide a comprehensive overview of connections.
- **Threat Intelligence Integration**: Automatically checks public IP addresses against a well-known blocklist (`FireHOL`) and visually flags potentially malicious nodes in the graph.
- **Rich Node Information**: Enriches IP addresses with crucial metadata through background lookups:
- **Hostname Resolution (DNS)**: Displays hostnames instead of raw IP addresses.
- **Ownership Info (WHOIS)**: Shows the ASN description for public IPs.
- **Device Vendor (MAC Lookup)**: Identifies the manufacturer of local devices.
- **Interactive UI Dashboard**: A clean web interface allows you to start, stop, and clear the capture session. Click on any node to see a detailed panel with its connections, traffic volume, and enriched data.
- **Device Categorization**: Automatically categorizes nodes as "My Device", "Local Device", or "Internet" for immediate contextual understanding.

## 📂 Project Structure

The project is organized into modular components for clarity and maintainability.

```
.
├── README.md
├── requirements.txt
└── src
    ├── capture
    │   ├── __init__.py
    │   └── sniffer.py
    ├── config
    │   ├── __init__.py
    │   └── settings.py
    ├── core
    │   ├── __init__.py
    │   └── network_graph.py
    ├── logs
    │   └── logs.log
    ├── main.py
    ├── utils
    │   ├── __init__.py
    │   ├── logger.py
    │   ├── services.py
    │   └── threat_intel.py
    └── web
        ├── app.py
        ├── __init__.py
        └── templates
            ├── index.html
            ├── script.js
            └── style.css
```

## 🚀 Getting Started

Follow these instructions to get NetScope up and running on your system.

### Prerequisites

Before you begin, ensure you have the following installed:

- **Root Access**: The script must be run with `sudo` privileges to capture network packets.
- **Python 3**: Version 3.8 or higher is recommended.
- **Tshark**: The command-line utility for Wireshark. This is essential for packet sniffing.

  ```bash
  # For ArchLinux/Arch-based systems
  sudo pacman -Syu wireshark-cli
  ```

  ```bash
  # For Ubuntu/Debian-based systems
  sudo apt update
  sudo apt install tshark
  ```

  > **Note:** During the Tshark installation on Debian/Ubuntu, it will ask "Should non-superusers be able to capture packets?". Select **Yes**.

- **Python Libraries**: All required libraries are listed in the `requirements.txt` file.

### Installation & Usage

1.  **Clone the repository (or download the source code):**

    ```bash
    git clone "https://github.com/awmiriiw/netscope.git"
    cd netscope
    ```

2.  **Install the required Python packages:**

    run:

    ```bash
    # Install dependencies
    sudo pip3 install -r requirements.txt --break-system-packages
    ```

3.  **Configure the Network Interface:**
    Create a `.env` file in the root directory of the project. This file will tell NetScope which network interface to monitor.

    ```bash
    # Find your network interface name (e.g., eth0, wlan0, enp4s0)
    ip addr

    # Create and edit the .env file
    echo "NETWORK_INTERFACE=your_interface_name" > .env
    ```

    Replace `your_interface_name` with the actual name from the `ip addr` command.

4.  **Run the application:**
    The main script starts the packet sniffer and the web server.

    ```bash
    sudo python3 src/main.py
    ```

5.  **Open the Dashboard:**
    Once the server is running, open your web browser and navigate to:
    **[http://127.0.0.1:8080](http://127.0.0.1:8080)**

    You can now use the controls on the dashboard to start capturing and visualizing your network traffic.

## 📝 License

This project is open-source and available under the [GNU AGPLv3 License](https://opensource.org/license/agpl-v3).

**Thanks for visiting! ☕**
