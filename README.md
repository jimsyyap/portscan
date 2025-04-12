# Port Scanner

A fast and flexible port scanner written in Go, designed for network security auditing and reconnaissance. It supports TCP SYN and Connect scanning, with features like banner grabbing, service detection, and customizable output.

**⚠️ Legal Notice**: This tool is intended for ethical use only. Always obtain explicit permission before scanning networks or systems you do not own. Unauthorized scanning may violate laws and regulations.

## Features

- **TCP SYN Scanning**: Stealthy half-open scanning (requires root privileges).
- **TCP Connect Scanning**: Full-connection scanning (no root required).
- **Service Detection**: Maps common ports to services (e.g., 80 → HTTP).
- **Banner Grabbing**: Retrieves service banners for open ports (e.g., "Apache/2.4.41").
- **Flexible Targets**: Supports IPs, CIDR ranges (e.g., `10.0.0.0/24`), and hostnames.
- **Port Specification**: Accepts single ports, ranges (e.g., `1-1000`), or comma-separated lists.
- **Concurrency Control**: Adjustable concurrency for performance tuning.
- **Stealth Options**: Configurable inter-packet delay to reduce detection risk.
- **Output Formats**: Text (colorized) or JSON, with optional file logging.
- **Progress Feedback**: Real-time scan progress updates.
- **Verbose Logging**: Detailed debugging output for troubleshooting.

## Prerequisites

- **Go**: Version 1.18 or higher.
- **Dependencies**:
  - `github.com/google/gopacket`
  - `github.com/fatih/color`
  - `golang.org/x/sync/semaphore`
- **Root Privileges**: Required for SYN scanning (not for Connect scanning).
- **libpcap**: Needed for packet capture (SYN scanning).
  - Ubuntu/Debian: `sudo apt-get install libpcap-dev`
  - macOS: `brew install libpcap`
  - Windows: Install Npcap (https://npcap.com)

## Installation

1. Clone the repository:
   ```bash
   git clone <your-repo-url>
   cd <repo-name>
   ```

2. Install dependencies:
   ```bash
   go mod init portscanner
   go get github.com/google/gopacket
   go get github.com/fatih/color
   go get golang.org/x/sync/semaphore
   ```

3. Build the scanner:
   ```bash
   go build -o portscanner claude.go
   ```

## Usage

Run the scanner with various flags to customize behavior. Examples:

```bash
# SYN scan with default settings (ports 1-1024)
sudo ./portscanner -t 192.168.1.1

# Connect scan (no root) with specific ports
./portscanner -t 192.168.1.1 -p 80,443 -scan-type connect

# Scan a CIDR range with banner grabbing and JSON output
sudo ./portscanner -t 10.0.0.0/24 -p 80,443 -banner -json

# Stealth scan with delay and logging
sudo ./portscanner -t 192.168.1.1 -p 1-100 -delay 10ms -log scan.log -v

# High-concurrency scan with progress feedback
sudo ./portscanner -t 10.0.0.0/24 -p 22,80,443 -c 1000
```

### Flags

- `-t`: Targets (e.g., `192.168.1.1`, `10.0.0.0/24`, `example.com`).
- `-p`: Ports (e.g., `80`, `1-1000`, `80,443`).
- `-scan-type`: Scan type (`syn` or `connect`, default: `syn`).
- `-banner`: Enable banner grabbing for open ports.
- `-service`: Enable service name lookup (default: true).
- `-c`: Concurrency limit (default: 500).
- `-delay`: Delay between scans (e.g., `10ms`).
- `-i`: Network interface (default: auto-detect).
- `-timeout`: Scan timeout (default: 2s).
- `-json`: Output results in JSON format.
- `-log`: Save results to a file.
- `-v`: Enable verbose logging.

## Example Output

**Text Output**:
```
192.168.1.1     80       OPEN     HTTP (Apache/2.4.41)
192.168.1.1     443      OPEN     HTTPS
```

**JSON Output**:
```json
[
  {
    "target": "192.168.1.1",
    "port": 80,
    "status": "open",
    "service": "HTTP",
    "banner": "Apache/2.4.41",
    "timestamp": "2025-04-12T10:00:00Z"
  }
]
```

## Notes

- **SYN Scanning**: Requires root privileges (`sudo`) due to raw packet manipulation.
- **Connect Scanning**: Slower but works without root and is less likely to be blocked.
- **Banner Grabbing**: May slow scans slightly; use `-banner` selectively.
- **Logging**: Use `-log` for audits; combine with `-v` for debugging.
- **Stealth**: Use `-delay` to reduce network noise, but test delays to balance speed and stealth.

## Contributing

Contributions are welcome! Please:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-name`).
3. Commit changes (`git commit -m "Add feature"`).
4. Push to the branch (`git push origin feature-name`).
5. Open a pull request.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- Built with [Go](https://golang.org) and [gopacket](https://github.com/google/gopacket).
- Inspired by tools like Nmap and Masscan.
