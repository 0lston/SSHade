import logging
from typing import Tuple, Optional, Dict, Any
import json
import time
import uuid

logger = logging.getLogger('c2.session')

class ClientSession:
    """Represents a connected client session"""
    
    def __init__(self, channel, client_info: str, addr: Tuple[str, int], transport_type: str):
        self.id = str(uuid.uuid4())
        self.channel = channel
        self.client_info = client_info
        self.addr = addr
        self.is_active = True
        self.transport_type = transport_type  # 'ssh', 'http', etc.
        self.hostname = None
        self.username = None
        self.os_type = None
        self.connect_time = time.time()
        self.last_seen = time.time()
        self.capabilities = []
        self._parse_client_info()
    
    def _parse_client_info(self):
        """Parse the client info string to extract client details"""
        try:
            # Try parsing as JSON first (newer clients)
            try:
                info = json.loads(self.client_info)
                self.hostname = info.get('hostname')
                self.username = info.get('username')
                self.os_type = info.get('os')
                self.capabilities = info.get('capabilities', [])
                return
            except json.JSONDecodeError:
                pass
                
            # Fall back to string parsing (older clients)
            if "Implant checked in from" in self.client_info:
                parts = self.client_info.split()
                self.hostname = parts[4]
                self.username = parts[6]
                self.os_type = "Unknown"
                
        except Exception as e:
            logger.warning(f"Couldn't parse client info: {self.client_info}, error: {e}")
            
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for serialization"""
        return {
            'id': self.id,
            'hostname': self.hostname,
            'username': self.username,
            'addr': f"{self.addr[0]}:{self.addr[1]}",
            'os_type': self.os_type,
            'transport': self.transport_type,
            'active': self.is_active,
            'connect_time': self.connect_time,
            'last_seen': self.last_seen,
            'uptime': round(time.time() - self.connect_time, 2),
            'capabilities': self.capabilities
        }
    
    def update_last_seen(self):
        """Update the last seen timestamp"""
        self.last_seen = time.time()
    
    def send_command(self, command: str) -> Optional[str]:
        """Send a command to the client and get response"""
        try:
            if not self.is_active:
                return "Error: Client is not active"
                
            if self.transport_type == 'ssh':
                return self._send_ssh_command(command)
            elif self.transport_type == 'http':
                return self._send_http_command(command)
            else:
                return f"Error: Unsupported transport type: {self.transport_type}"
        except Exception as e:
            logger.error(f"Error sending command: {e}")
            self.is_active = False
            return f"Error: {str(e)}"
    
    def _send_ssh_command(self, command: str) -> str:
        """Send command via SSH channel"""
        try:
            self.channel.send(command)
            response = self.channel.recv(16384).decode(errors='replace')
            self.update_last_seen()
            return response
        except Exception as e:
            logger.error(f"SSH command error: {e}")
            self.is_active = False
            raise
    
    def _send_http_command(self, command: str) -> str:
        """Send command via HTTP channel"""
        # This is a placeholder for the HTTP implementation
        # The actual implementation would depend on how the HTTP transport works
        try:
            return self.channel.send_command(command)
        except Exception as e:
            logger.error(f"HTTP command error: {e}")
            self.is_active = False
            raise
    
    def __str__(self):
        return f"{self.username}@{self.hostname} ({self.addr[0]}:{self.addr[1]}) [{self.transport_type}]"