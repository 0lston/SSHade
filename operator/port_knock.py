import socket
import threading
import time
from collections import defaultdict
import logging

class PortKnockHandler:
    def __init__(self, knock_sequence, timeout=30):
        """
        Initialize port knock handler
        knock_sequence: List of ports that need to be knocked in sequence
        timeout: Time in seconds before knock sequence expires
        """
        self.knock_sequence = knock_sequence
        self.timeout = timeout
        self.knock_trackers = defaultdict(list)
        self.allowed_ips = set()
        self.lock = threading.Lock()
        self.logger = logging.getLogger('PortKnock')
        
    def start_listeners(self, bind_address):
        """Start listeners for knock ports"""
        for port in self.knock_sequence:
            thread = threading.Thread(
                target=self._port_listener,
                args=(bind_address, port)
            )
            thread.daemon = True
            thread.start()

    def _port_listener(self, bind_address, port):
        """Listen for knocks on specified port"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((bind_address, port))
            sock.listen(5)
            while True:
                try:
                    client_sock, addr = sock.accept()
                    client_sock.close()
                    self._handle_knock(addr[0], port)
                except Exception as e:
                    self.logger.error(f"Error in port listener: {e}")
        except Exception as e:
            self.logger.error(f"Failed to bind to port {port}: {e}")
        finally:
            sock.close()

    def _handle_knock(self, ip, port):
        """Handle a knock from an IP address"""
        with self.lock:
            current_time = time.time()
            knocks = self.knock_trackers[ip]
            
            # Remove expired knocks
            knocks = [k for k in knocks if current_time - k[1] <= self.timeout]
            
            # Add new knock
            knocks.append((port, current_time))
            self.knock_trackers[ip] = knocks
            
            # Check if sequence is complete
            if self._check_sequence(ip):
                self.logger.info(f"Successful knock sequence from {ip}")
                self.allowed_ips.add(ip)
                # Clear knock history for this IP
                self.knock_trackers[ip] = []

    def _check_sequence(self, ip):
        """Check if the knock sequence is correct"""
        knocks = [k[0] for k in self.knock_trackers[ip]]
        sequence_length = len(self.knock_sequence)
        
        if len(knocks) < sequence_length:
            return False
            
        return knocks[-sequence_length:] == self.knock_sequence

    def is_ip_allowed(self, ip):
        """Check if IP is allowed to connect"""
        with self.lock:
            if ip in self.allowed_ips:
                self.allowed_ips.remove(ip)  # One-time access
                return True
        return False
