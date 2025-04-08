import socket
import threading
import logging
import time
from typing import List, Dict

logger = logging.getLogger('PortKnockHandler')

class PortKnockHandler:
    """Handler for port knocking authentication"""
    
    def __init__(self, knock_sequence: List[int], timeout: int = 10):
        self.knock_sequence = knock_sequence
        self.timeout = timeout  # seconds
        self.allowed_ips: Dict[str, float] = {}
        self.knock_state: Dict[str, List[int]] = {}
        self.listeners: List[threading.Thread] = []
        self.running = False
    
    def start_listeners(self, bind_address: str):
        """Start listeners for each port in the knock sequence"""
        self.running = True
        for i, port in enumerate(self.knock_sequence):
            thread = threading.Thread(
                target=self._listen_for_knock,
                args=(bind_address, port, i)
            )
            thread.daemon = True
            thread.start()
            self.listeners.append(thread)
            logger.info(f"Started knock listener on port {port}")
    
    def stop_listeners(self):
        """Stop all knock listeners"""
        self.running = False
        # Sockets will be closed in the listener threads
        for thread in self.listeners:
            thread.join(1.0)  # Give threads 1 second to terminate
    
    def _listen_for_knock(self, bind_address: str, port: int, sequence_position: int):
        """Listen for knocks on a specific port"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(1.0)  # Short timeout to allow stopping
        
        try:
            sock.bind((bind_address, port))
            sock.listen(5)
            
            while self.running:
                try:
                    # Accept connections with timeout
                    client_socket, addr = sock.accept()
                    client_socket.close()  # No need to keep connection open
                    
                    client_ip = addr[0]
                    self._handle_knock(client_ip, sequence_position)
                    
                except socket.timeout:
                    # This is expected due to the timeout we set
                    continue
                except Exception as e:
                    logger.error(f"Error in knock listener on port {port}: {e}")
        finally:
            sock.close()
    
    def _handle_knock(self, client_ip: str, sequence_position: int):
        """Handle a knock from a client"""
        current_time = time.time()
        
        # Initialize or update knock state
        if client_ip not in self.knock_state:
            self.knock_state[client_ip] = []
        
        # Check if this is the next expected knock in sequence
        next_expected = len(self.knock_state[client_ip])
        if sequence_position == next_expected:
            self.knock_state[client_ip].append(sequence_position)
            logger.debug(f"{client_ip} completed knock {sequence_position+1}/{len(self.knock_sequence)}")
            
            # Check if sequence is complete
            if len(self.knock_state[client_ip]) == len(self.knock_sequence):
                logger.info(f"{client_ip} completed knock sequence, allowing access")
                self.allowed_ips[client_ip] = current_time + self.timeout
                self.knock_state.pop(client_ip)
        else:
            # Reset on incorrect sequence
            logger.debug(f"{client_ip} sent incorrect knock, resetting sequence")
            self.knock_state[client_ip] = []
    
    def is_ip_allowed(self, client_ip: str) -> bool:
        """Check if an IP is allowed based on completed knock sequence"""
        current_time = time.time()
        
        # Clean up expired entries
        expired = [ip for ip, expire_time in self.allowed_ips.items() if expire_time < current_time]
        for ip in expired:
            self.allowed_ips.pop(ip)
        
        return client_ip in self.allowed_ips