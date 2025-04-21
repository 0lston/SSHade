import logging
from typing import Tuple, Optional, Dict, Any
import json
import time
import uuid

logger = logging.getLogger('c2.session')

class ClientSession:
    """Represents a connected client session"""
    
    def __init__(self, channel, client_info: str, addr: Tuple[str, int], transport_type: str, 
                 pty_enabled: bool = False, term_settings: Dict = None):
        self.id = str(uuid.uuid4())
        self.channel = channel
        self.client_info = client_info
        self.addr = addr
        self.is_active = True
        self.transport_type = transport_type  # 'ssh', 'http', etc.
        self.hostname = None
        self.pty_enabled = pty_enabled
        self.term_settings = term_settings or {}
        self._parse_client_info()
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
        data = {
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
            'capabilities': self.capabilities,
            'pty_enabled': self.pty_enabled,
        }
    
        if self.pty_enabled:
            data['terminal'] = {
                'type': self.term_settings.get('term'),
                'size': f"{self.term_settings.get('width')}x{self.term_settings.get('height')}"
            }
        return data
    
    def resize_pty(self, width: int, height: int) -> bool:
        """Handle terminal resize events"""
        if not (self.pty_enabled and self.channel):
            return False
            
        try:
            self.channel.resize_pty(width=width, height=height)
            self.term_settings['width'] = width
            self.term_settings['height'] = height
            logger.debug(f"Resized PTY to {width}x{height}")
            return True
        except Exception as e:
            logger.error(f"Failed to resize PTY: {e}")
            return False
    def update_last_seen(self):
        """Update the last seen timestamp"""
        self.last_seen = time.time()
    
    def disconnect(self):
        """Cleanly disconnect the client session"""
        try:
            if self.channel:
                if hasattr(self.channel, 'transport') and self.channel.transport:
                    self.channel.transport.close()
                self.channel.close()
            self.is_active = False
            logger.info(f"Client disconnected: {self}")
            return True
        except Exception as e:
            logger.error(f"Error disconnecting client: {e}")
            return False
    

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
            if not self.channel or not self.channel.active:
                raise Exception("Channel not active")
                
            if self.pty_enabled:
                # For PTY sessions, properly format command and handle output
                command = command.strip() + '\r'  # Use \r instead of \n for Windows
                self.channel.send(command)
                
                # More sophisticated buffered reading for PTY mode
                response = ''
                timeout = time.time() + 2.0  # Longer initial timeout
                accumulated_data = False
                
                while True:
                    if self.channel.recv_ready():
                        chunk = self.channel.recv(1024).decode(errors='replace')
                        response += chunk
                        timeout = time.time() + 0.2  # Reset timeout after receiving data
                        accumulated_data = True
                    elif accumulated_data and time.time() > timeout:
                        # Only break if we've received some data and hit timeout
                        break
                    elif not accumulated_data and time.time() > timeout:
                        # Initial timeout without data
                        break
                    else:
                        time.sleep(0.005)  # Shorter sleep interval
                
                # Clean up the response
                response = self._clean_pty_response(response, command)
                self.update_last_seen()
                return response
            else:
                # Non-PTY mode remains the same
                self.channel.send(command)
                response = self.channel.recv(16384).decode(errors='replace')
                self.update_last_seen()
                return response
                
        except Exception as e:
            logger.error(f"SSH command error: {e}")
            self.is_active = False
            raise

    def _clean_pty_response(self, response: str, command: str) -> str:
        """Clean up PTY response by removing echo and handling prompt"""
        try:
            # Split into lines
            lines = response.split('\r\n')
            
            # Remove command echo if present
            if lines and command.strip() in lines[0]:
                lines.pop(0)
            
            # Remove empty lines from the start
            while lines and not lines[0].strip():
                lines.pop(0)
                
            # Remove prompt and empty lines from the end
            while lines and (not lines[-1].strip() or 
                            self.username in lines[-1] or 
                            '>' in lines[-1] or 
                            '$' in lines[-1]):
                lines.pop()
                
            # Rejoin with proper line endings
            return '\n'.join(lines) + '\n' if lines else ''
            
        except Exception as e:
            logger.error(f"Error cleaning PTY response: {e}")
            return response
    
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