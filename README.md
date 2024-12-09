# Network_and_port_scanner

This script performs port scanning on a target IP address or a range of IP addresses. It utilizes the Scapy library for network packet manipulation and nmap for service identification.

**Features:**

* Supports single IP addresses and CIDR notation for IP ranges.
* Scans specified ports or a range of ports.
* Identifies open and closed ports.
* Displays the service associated with each open port (if available).
* Includes basic error handling.

**Usage:**

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Gaurav909565/Network_and_port_scanner.git
   ```

2. **Navigate to the repository:**
   ```bash
   cd Network_and_port_scanner/
   ```

3. **Run the script:**
   ```bash
   python scanner.py -t <target> -p <port> 
   ```
   * **-t, --target:** Specify the target IP address or CIDR notation (e.g., 192.168.1.1 or 192.168.1.0/24).
   * **-p, --port:** Specify the port or range of ports to scan (e.g., 80, 22, 21 or 1-1024 or 22,80,443).

**Example:**

```bash
python scanner.py -t 192.168.1.1 -p 22,80 
```

This will scan the IP address 192.168.1.1 for ports 22 and 80.

**Note:**

* This script requires the Scapy, nmap, and ipaddress libraries. Install them using:
   ```bash
   pip install scapy nmap ipaddress
   ```
* Port scanning should be conducted responsibly and ethically. 
* Always obtain proper authorization before scanning any systems.

This description provides a concise and informative overview of the port scanning script, including its functionality, usage instructions, and required libraries. It also emphasizes responsible and ethical usage.
