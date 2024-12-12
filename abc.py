import socket
import threading
import queue
import sys
from datetime import datetime

def scan_port(target, port, open_ports):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            service = "unknown"
            try:
                service = socket.getservbyport(port)
            except:
                pass
            open_ports.append((port, service))
        sock.close()
    except:
        pass

def port_scanner(target, start_port=1, end_port=1024, num_threads=100):
    """Main port scanner function"""
    try:
        # Resolve target IP if domain name is provided
        target_ip = socket.gethostbyname(target)
        print(f"\nStarting scan on host: {target_ip}")
        print(f"Time started: {datetime.now()}\n")

        # Queue to hold ports to scan
        port_queue = queue.Queue()
        open_ports = []

        # Add ports to queue
        for port in range(start_port, end_port + 1):
            port_queue.put(port)

        # Create and start threads
        threads = []
        for _ in range(num_threads):
            thread = threading.Thread(target=worker, args=(target_ip, port_queue, open_ports))
            thread.daemon = True
            thread.start()
            threads.append(thread)

        # Wait for port queue to be empty
        port_queue.join()

        # Print results
        print("\nScan completed!")
        print(f"Open ports on {target_ip}:")
        if open_ports:
            for port, service in sorted(open_ports):
                print(f"Port {port}: {service}")
        else:
            print("No open ports found.")

    except socket.gaierror:
        print("\nHostname could not be resolved.")
    except socket.error:
        print("\nCouldn't connect to server.")
    except KeyboardInterrupt:
        print("\nExiting program.")
        sys.exit()

def worker(target, port_queue, open_ports):
    """Worker function for threads"""
    while True:
        try:
            port = port_queue.get_nowait()
            scan_port(target, port, open_ports)
            port_queue.task_done()
        except queue.Empty:
            break

def vulnerability_check(target, port):
    """Basic vulnerability checking"""
    common_vulns = {
        21: "FTP - Anonymous login might be enabled",
        23: "Telnet - Unencrypted traffic",
        53: "DNS - Potential for DNS zone transfer",
        80: "HTTP - Check for common web vulnerabilities",
        443: "HTTPS - Verify SSL/TLS version",
        3306: "MySQL - Check for default credentials",
        3389: "RDP - Check for BlueKeep vulnerability"
    }
    return common_vulns.get(port, "No common vulnerabilities known")

if __name__ == "__main__":
    print("Simple Port Scanner")
    print("-" * 50)
    
    target = input("Enter target IP or domain: ")
    start_port = int(input("Enter starting port (default 1): ") or 1)
    end_port = int(input("Enter ending port (default 1024): ") or 1024)
    threads = int(input("Enter number of threads (default 100): ") or 100)
    
    port_scanner(target, start_port, end_port, threads)
