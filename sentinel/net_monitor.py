import socket
from sentinel.sentinel_event import SentinelEvent

# These are ports that should raise suspicion if found open
# on a machine that doesn't intentionally run these services
SUSPICIOUS_PORTS = {
    21: "FTP",
    23: "Telnet",
    135: "Windows RPC",
    445: "Windows SMB",
    902: "VMware Auth",
    912: "VMware Auth",
    3306: "MySQL",
    5900: "VNC",
    6379: "Redis",
    27017: "MongoDB"
}


def scan_ports(host: str = "127.0.0.1", port_range: range = range(1, 1025)) -> list:
    """
    Scans the given host for open ports.
    Returns a list of SentinelEvent objects — one per open port.
    """
    events = []
    print(f"[Net] Scanning {host} on ports {port_range.start}–{port_range.stop - 1}...")

    for port in port_range:
        # Create a fresh TCP socket for each port
        # AF_INET = IPv4, SOCK_STREAM = TCP connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # settimeout(0.3) means: give up after 0.3 seconds if no response
        # Without this, a closed port could hang for 30+ seconds
        sock.settimeout(0.3)

        # connect_ex returns 0 if the connection succeeds (port is open)
        # Any other return code means the port is closed or filtered
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            # Determine severity based on whether the port is on our suspicious list
            severity = 4 if port in SUSPICIOUS_PORTS else 2
            service = SUSPICIOUS_PORTS.get(port, "Unknown service")

            event = SentinelEvent(
                event_type="Network",
                source=f"{host}:{port}",
                severity=severity,
                description=f"Open port detected: {port} ({service})"
            )
            events.append(event)
            print(f"[Net] OPEN → {host}:{port} ({service}) — severity {severity}")

    return events