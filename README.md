
# Network Sniffer

This is a network sniffer implemented using sockets in Python. It is compatible with UNIX-based operating systems and captures network traffic, recognizing multiple protocols such as IPv4, IPv6, ARP, Wake-on-LAN, LLDP, MAC Security, ICMPv4, ICMPv6, UDP, TCP, and NDP.

## Prerequisites

- Python 2.7.12 or above
- Root or administrative privileges to capture network traffic
- UNIX-based operating system (Linux, macOS, etc.)

## Setup

1. **Clone the repository**:
    \`\`\`bash
    git clone https://github.com/Omarallaham58/CodeAlpha_Network_Sniffer.git
   
    cd network-sniffer
    \`\`\`

3. **Ensure the \`list_interfaces\` script is executable**:
    \`\`\`
    chmod +x list_interfaces
    \`\`\`

4. **Install any necessary Python packages**:
    The script primarily uses standard libraries, but you may need additional packages depending on your environment.

## Usage

1. **Run the network sniffer**:
    \`\`\`
    sudo python3 network_sniffer.py <interface>
    \`\`\`
    Replace \`<interface>\` with the name of the network interface you want to capture traffic on (e.g., \`eth0\`).

2. **Example**:
    \`\`\`
    sudo python3 network_sniffer.py eth0
    \`\`\`



## Contributing

Contributions are welcome! Please fork the repository and submit a pull request for any enhancements or bug fixes.

## Contact

For any questions or comments, please open an issue on GitHub or contact the project maintainer at [omarallaham58@gmail.com].
