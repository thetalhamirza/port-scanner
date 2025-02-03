# Port Scanner

A powerful, multithreaded port scanner written in Python, capable of performing network-wide ping sweeps and detailed port scans. This script includes features like threading and customizable thread counts which greatly improves its speed.

## Features

- **Ping Sweep:** Identifies live hosts within a specified network range.
- **Port Scanning:** Scans common ports (1-1023) on live hosts to detect open ports.
- **Multithreading:** Utilizes multithreading for faster scanning. Users can specify the number of threads for optimized performance.
- **Color-Coded Output:** Enhances readability with colored status updates.
- **Efficient Resource Usage:** Locks ensure clean, thread-safe console output.

## Usage

```bash
python port_scanner.py <network> <netmask> [threads]
```

### Parameters:

- `<network>`: The network IP (e.g., `192.168.1.0`).
- `<netmask>`: The subnet mask (e.g., `24`).
- `[threads]` _(optional)_: Number of threads to be used. Defaults to **50** if not provided.

### Example:

```bash
python port_scanner.py 192.168.1.0 24 100
```

This will scan the `192.168.1.0/24` network using **100 threads**.

## Requirements

- **Python 3**
- **Libraries:**
    - `scapy`
    - `ipaddress`
    - `concurrent.futures`
    - `colorama`
    - `termcolor`

Install dependencies with:

```bash
pip install scapy colorama termcolor
```

## How It Works

1. **Ping Sweep:** The script sends ICMP requests to identify live hosts.
2. **Port Scanning:** For each live host, TCP SYN packets are sent to ports 1-1023.
3. **Multithreading:** Both ping sweeps and port scans leverage threading for faster execution.
4. **Output:** Displays online hosts and their open ports in a user-friendly format.

## Example Output

```
[+] Default threads set: 50

[>] Host 192.168.1.5 is online.
[>] Port 22 is open on host 192.168.1.5
[>] Port 80 is open on host 192.168.1.5

--> Host 192.168.1.5 has the following open ports: [22, 80]
```

## License

This project is for educational and ethical use only. Always ensure you have permission before scanning networks.

## Credits

Special thanks to **faanross** for the inspiring tutorial that guided the development of this script.