"""
Port scanning module
Responsible for TCP connection logic and network error handling
"""

# Provides symbolic names for system error codes, such as ETIMEDOUT.
import errno
# Provides low-level networking interface for TCP/IP connections
import socket
# Type hints for better code documentation and IDE support
# List: list of values, Dict: key-value pairs, Any: any type
from typing import List, Dict, Any
# Professional logging system for tracking events and debugging
# Levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
import logging
# Provides timestamp functionality for scan reports
# datetime.now() gives current date and time
from datetime import datetime
# Provides multithreading support for concurrent port scanning
from concurrent.futures import ThreadPoolExecutor, as_completed

# Create logger for this module
logger = logging.getLogger(__name__)

class PortScanner:
    """
    Handles TCP port scanning logic.

    This class encapsulates all network-related operations. It doesn't know
    about configuration files or report generation - its only job is to 
    attempt connections and report what it finds. 

    Atributes:
        timeout(float): Maximum second to wair for connection. 
    """
    def __init__(self, timeout: float = 1.0):
        """
        Initializes the PortScanner with a specified timeout.

        Args:
            timeout (float): Connection timeout in seconds. Increase for slow networks.
        """
        self.timeout = timeout
        self.open_ports=[] 
        self.closed_ports=[]
        self.filtered_ports=[]
        self.error_ports = []

    def scan_port(self, ip: str, port: int) -> Dict[str, Any]:
        """
        Scan a single TCP port on a target IP address.

        This method attempts to establish a TCP connection to the specified
        port. The scanner classifies the outcome using the return value
        or the exception raised by the connection attempt.

        Port states:
            - 'open': Successful TCP connection (service is listening)
            - 'closed': Connection failed or explicitly refused
            - 'filtered': The connection attempt timed out. The cause of the
            timeout remains unknown.
            - 'error': Unexpected issue (e.g., DNS failure, invalid IP)

        Args:
            ip (str): Target IP address (e.g., '192.168.1.1')
            port (int): Port number to scan (range: 1–65535)

        Returns:
            Dict[str, Any]: Dictionary containing scan result with structure:
                {
                    'port': int,           # Port number scanned
                    'state': str,          # Port state (open/closed/filtered/error)
                    'service': str | None, # Detected service name (if available)
                    'error': str | None    # Error message (if applicable)
                }
        """
        result = {
            'port': port,
            'state': 'unknown',
            'service': None,
            'error': None
        }

        sock = None

        try:
            # Create TCP socket (IPv4, stream-based connection)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Set timeout to prevent blocking on unresponsive ports
            sock.settimeout(self.timeout)

            # Attempt TCP connection (returns 0 if successful)
            connection_result = sock.connect_ex((ip, port))

            if connection_result == 0:
                # Connection successful → port is OPEN
                result['state'] = 'open'

                # Try to resolve known service name (e.g., 80 → http)
                try:
                    result['service'] = socket.getservbyport(port)
                except OSError:
                    # Service not recognized in system database
                    result['service'] = 'unknown'

                logger.info(f"Port {port}: OPEN")

            # Handle a timeout returned as an error code by connect_ex().
            # The socket.timeout handler covers the raised exception.
            elif connection_result == errno.ETIMEDOUT:
                result['state'] = 'filtered'
                logger.debug(f"Port {port}: FILTERED (timeout code)")

            else:
                # Treat other nonzero connection codes as closed.
                result['state'] = 'closed'
                logger.info(f"Port {port}: CLOSED")

        except socket.timeout:
            # Record the timeout without attributing it to a specific cause.
            result['state'] = 'filtered'
            logger.debug(f"Port {port}: FILTERED (timeout)")

        except ConnectionRefusedError:
            # Explicit refusal → port is CLOSED
            result['state'] = 'closed'
            logger.debug(f"Port {port}: CLOSED (connection refused)")

        except socket.gaierror as e:
            # Address-related error (DNS resolution failure)
            result['state'] = 'error'
            result['error'] = f"DNS error - {e}"
            logger.error(f"Port {port}: DNS ERROR - {e}")

        except Exception as e:
            # Any other unexpected exception
            result['state'] = 'error'
            result['error'] = str(e)
            logger.error(f"Port {port}: Unexpected error - {e}")

        finally:
            # Ensure socket is always closed to free system resources
            if sock:
                sock.close()

        # Store result for later summary/statistics
        if result['state'] == 'open':
            self.open_ports.append(result)
        elif result['state'] == 'closed':
            self.closed_ports.append(result)
        elif result['state'] == 'filtered':
            self.filtered_ports.append(result)
        elif result['state'] == 'error':
            self.error_ports.append(result)

        return result

    def scan_ports(self, ip: str, ports: List[int]) -> List[Dict[str, Any]]:
        """
        Scan multiple ports on a target IP using multithreading.

        This method distributes port scanning tasks across multiple threads
        to significantly improve performance compared to sequential scanning.

        Args:
            ip (str): Target IP address
            ports (List[int]): List of ports to scan

        Returns:
            List[Dict[str, Any]]: List of scan results
        """

        # Clear previous scan results
        self.open_ports.clear()
        self.closed_ports.clear()
        self.filtered_ports.clear()
        self.error_ports.clear()

        results = []
        total = len(ports)

        print(f"\nScanning {ip} - {total} ports (multithreaded)...")
        print("-" * 50)

        # Define number of threads (max 100 or total ports)
        max_threads = min(100, total)

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, ip, port): port
                for port in ports
            }

            for idx, future in enumerate(as_completed(future_to_port), 1):
                port = future_to_port[future]

                try:
                    result = future.result()
                    results.append(result)

                    print(f"Progress: {idx}/{total} - Port {port} done", end='\r')

                except Exception as e:
                    logger.error(f"Error scanning port {port}: {e}")

        print("\n" + "-" * 50)
        print(f"SCAN COMPLETE. Open ports found: {len(self.open_ports)}")
        print("=" * 50)

        return results

    def get_open_ports(self) -> list:
        """ Returns a list of open ports found during the scan."""
        return [p['port'] for p in self.open_ports]
    
    def get_summary(self) -> Dict[str, Any]:
        """ 
        Generates summary statistics of the last scan.

        The total includes open, closed, filtered, and failed attempts.

        Returns:
            Dictionary with scan statistics
        """
        return {
            'total_scanned': len(self.open_ports) + len(self.closed_ports) + 
            len(self.filtered_ports) + len(self.error_ports),
            'open_count': len(self.open_ports),
            'closed_count': len(self.closed_ports),
            'filtered_count': len(self.filtered_ports),
            'error_count': len(self.error_ports),
            'open_ports_list': self.get_open_ports()
        }
                
            

                