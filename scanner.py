"""
Port scanning module
Responsible for TCP connection logic and network error handling
"""
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

        def scan_port(selft, ip:str, port: int) -> Dict[str, Any]:
            """
            Sacan a single port on target IP address.

            This method attempts a TCP connection to the specified port and
            determines its sate based on the response. 

            Possible states:
                - open: Sussessful TCP hanshake (service is listening)
                - 'closed': Connection refused (no service on this port)
                - 'filtered': Timeout or no response (firewall likely present)
                - 'error': Network error or invalid IP

            Args:
                ip: Target Ip addres (e.g. '192.168.1.1')
                port: Port number to scan (1-65535)
            Returns:
                Dictionary with port information
                {
                    'port': int,
                    'state': str,
                    'service': str or None,
                    'error': str or None
                }
            """
            result = {
                'port': port,
                'state': 'unknown',
                'service': None,
                'error': None
            }

            try:
                # Create a TCP socket (IPv4)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                #Set timeout to avoid handing
                sock.settimeout(self.timeout)

                # Attement connetcion. connect_ex() returns 0 on success, error code ot herwise
                connection_result = sock.connect_ex((ip, port))    

                if connection_result == 0:
                    #Connection successful, port is open
                    result['state'] = 'open'
                    try:
                        result['service'] = socket.getservbyport(port)
                    except OSError:
                        result['service'] = 'unknown'

                        logger.info(f"Port{port}: OPEN")

                elif connection_result == 111:
                   #Connection refused, port is closed
                   result['state'] = 'closed'
                   logger.info(f"Port {port}: CLOSED")
                else:
                    #Other error codes typically indicate filtered state
                    result['state'] = 'filtered'
                    logger.info(f"Port {port}: FILTERED (error: {connection_result})")

            except socket.timeout:
                #No response within timeout, likely filtered
                result['state'] = 'filtered'
                logger.debug(f"Port {port}: FILTERED (timeout)")

            except socket.error as e:
                #DNS resulution failure or invalid IP
                result['state'] = 'error'
                result['error'] = f"DNS error - {e}"
                logger.error(f"Port {port}:DNS ERROR - {e}")

            except ConnectionRefusedError:
                #Explicit connection refusal, port is closed
                result['state'] = 'closed'
                logger.debug(f"Port {port}: CLOSED (connection refused)")

            except Exception as e:
                #Any other unexpected error
                result['state'] = 'error'
                result['error'] = str(e)
                logger.error(f"Port {port}: Unexpected error - {e}")

            #Track result for summary statistics
            if result['state'] == 'open':
                self.open_ports.append(result)
            elif result['state'] == 'closed':
                self.closed_ports.append(result)
            elif result['state'] == 'filtered':
                self.filtered_ports.append(result)

            return result
        
        def scan_ports(self, ip: str, ports: List[int]) -> List:
            """
            Scans multiple ports on target IP address.

            Iterates througth a list of ports and returns for each.

            Args:
                ip: Target IP address
                ports: List of port numbers to scan
            Returns:
                List of scan results ( each resilt is a dict from scan_port)
            """

            results = []
            total = len(ports)

            print(f"\nScanning {ip} - {total} ports to check...")
            print("-" * 50)

            for idx, port in enumerate(ports, 1):
                #Show progress on the same line 
                print(f"Progress: {idx}/{total} - Checking ports {port}....", end='\r')
                result = self.scan_port(ip, port)
                results.append(result)

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
            Returns:
                Dictionary with scan statistics
            """
            return{
                'total_scanned': len(self.open_ports) + len(self.closed_ports) + 
                len(self.filtered_ports),
                'open_count': len(self.open_ports),
                'closed_count': len(self.closed_ports),
                'filtered_count': len(self.filtered_ports),
                'open_ports_list': self.get_open_ports()
            }
                
            

                