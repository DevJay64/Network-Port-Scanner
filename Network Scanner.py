import socket
import sys
import threading
from queue import Queue

# --- Configuration ---
# Number of threads to use for scanning. More threads can scan faster,
# but might consume more resources or be blocked by firewalls.
NUM_THREADS = 50
# Timeout in seconds for connecting to a port. Lower values make the scan faster,
# but might miss open ports on slow networks.
CONNECTION_TIMEOUT = 1.0

# --- Global Data Structures ---
# Queue to hold ports that need to be scanned
port_queue = Queue()
# List to store results of the scan (open ports and their banners)
open_ports = []
# Lock to ensure thread-safe access to the open_ports list
print_lock = threading.Lock()

# --- Functions ---

def display_message(message, message_type="info"):
    """
    Displays a formatted message to the console.
    This replaces alert() for a command-line application.
    """
    if message_type == "error":
        print(f"\n[ERROR] {message}\n", file=sys.stderr)
    elif message_type == "success":
        print(f"\n[SUCCESS] {message}\n")
    else: # info
        print(f"[INFO] {message}")

def scan_port(target_ip, port):
    """
    Attempts to connect to a given port on the target IP.
    If successful, it tries to grab a service banner.
    """
    try:
        # Create a new socket object
        # AF_INET specifies IPv4 address family
        # SOCK_STREAM specifies TCP socket (for connection-oriented communication)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout for the connection attempt
        sock.settimeout(CONNECTION_TIMEOUT)

        # Attempt to connect to the target IP and port
        result = sock.connect_ex((target_ip, port)) # connect_ex returns an error indicator

        if result == 0: # Connection successful (port is open)
            banner = "No banner received"
            try:
                # Try to receive some data (banner) from the service
                # This is a basic attempt; some services might not send data immediately
                sock.sendall(b'HEAD / HTTP/1.0\r\n\r\n') # Example for HTTP
                sock.settimeout(0.5) # Shorter timeout for banner grab
                banner_data = sock.recv(1024) # Receive up to 1024 bytes
                banner = banner_data.decode('utf-8', errors='ignore').strip().split('\n')[0]
                if not banner:
                    banner = "Banner received, but empty/unreadable"
            except socket.timeout:
                banner = "No banner received (timeout)"
            except Exception as e:
                banner = f"Banner error: {e}"

            # Use a lock to ensure only one thread prints/modifies open_ports at a time
            with print_lock:
                open_ports.append({'port': port, 'banner': banner})
                print(f"Port {port}: Open - {banner}")
        # else:
            # Port is closed or filtered, no need to print for every closed port
            # print(f"Port {port}: Closed")

    except socket.gaierror:
        # Handle cases where the hostname/IP address cannot be resolved
        display_message(f"Hostname could not be resolved: {target_ip}", "error")
        sys.exit()
    except socket.error as e:
        # Handle general socket errors (e.g., network unreachable)
        display_message(f"Socket error during scan: {e}", "error")
        sys.exit()
    except Exception as e:
        # Catch any other unexpected errors
        display_message(f"An unexpected error occurred during scan: {e}", "error")
    finally:
        # Ensure the socket is closed whether connection was successful or not
        sock.close()

def worker():
    """
    Worker function for each thread. It continuously gets ports from the queue
    and scans them until the queue is empty.
    """
    while True:
        # Get a port from the queue. `True` makes it block until an item is available.
        # `timeout=1` makes it wait for 1 second before raising Empty exception
        # if no item is available (useful for graceful shutdown if queue is empty)
        port = port_queue.get()
        if port is None: # Sentinel value to signal thread to exit
            break
        scan_port(target_ip_global, port)
        # Signal that the task is done for this port
        port_queue.task_done()

# --- Main Execution ---

if __name__ == "__main__":
    # Global variable to hold the target IP, accessible by worker threads
    target_ip_global = ""

    display_message("Basic Network Scanner")
    display_message("This tool scans a target IP address for open TCP ports.")

    # Get target IP from user
    target_ip_global = input("Enter target IP address (e.g., 127.0.0.1): ").strip()

    # Basic IP address format validation
    # This is a simple regex and doesn't validate actual IP ranges (e.g., 256.x.x.x)
    # but covers common format errors.
    parts = target_ip_global.split('.')
    if not (len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)):
        display_message("Invalid IP address format. Please enter a valid IPv4 address.", "error")
        sys.exit(1)

    # Get port range from user
    try:
        start_port_str = input("Enter start port (e.g., 1): ").strip()
        end_port_str = input("Enter end port (e.g., 1024): ").strip()

        start_port = int(start_port_str)
        end_port = int(end_port_str)

        if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
            display_message("Invalid port range. Ports must be between 1 and 65535, and start port must be less than or equal to end port.", "error")
            sys.exit(1)

    except ValueError:
        display_message("Invalid port number. Please enter numeric values for ports.", "error")
        sys.exit(1)

    display_message(f"Scanning {target_ip_global} from port {start_port} to {end_port}...")

    # Populate the queue with ports to scan
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    # Create and start worker threads
    threads = []
    for _ in range(NUM_THREADS):
        thread = threading.Thread(target=worker)
        thread.daemon = True # Allows the main program to exit even if threads are running
        thread.start()
        threads.append(thread)

    # Wait for all tasks in the queue to be processed
    port_queue.join()

    # Add sentinel values to the queue to signal worker threads to exit gracefully
    for _ in range(NUM_THREADS):
        port_queue.put(None)

    # Wait for all threads to finish (they will exit after processing None)
    for thread in threads:
        thread.join()

    display_message("Scan complete.")

    # Print a summary of open ports
    if open_ports:
        display_message("\n--- Open Ports Summary ---", "success")
        # Sort open ports numerically for better readability
        open_ports.sort(key=lambda x: x['port'])
        for p_info in open_ports:
            print(f"Port {p_info['port']}: Open - {p_info['banner']}")
    else:
        display_message("No open ports found in the specified range.", "info")

