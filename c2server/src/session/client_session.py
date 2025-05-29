import logging
import signal
import select
import termios
import fcntl
import struct
import os
from typing import Tuple, Optional, Dict, Any, List
import json
import time
import uuid
import paramiko

logger = logging.getLogger('c2.session')

class PTYHandler:
    """Handles PTY-specific functionality for SSH sessions"""
    
    # ANSI control sequences
    ANSI_CLEAR = b"\x1b[2J\x1b[H"
    ANSI_RESET = b"\x1b[0m"
    
    # Common signal mappings
    SIGNAL_MAP = {
        signal.SIGINT: b"\x03",   # Ctrl+C
        signal.SIGTSTP: b"\x1a",  # Ctrl+Z
        signal.SIGQUIT: b"\x1c",  # Ctrl+\
        signal.SIGTERM: b"\x04",  # Ctrl+D (EOF)
    }
    
    def __init__(self, channel):
        self.channel = channel
        self.window_size = (80, 24)  # Default terminal size
        self.term_type = "xterm"     # Default terminal type
    
    def set_terminal_settings(self, term_type: str, width: int, height: int):
        """Configure terminal settings"""
        self.term_type = term_type
        self.window_size = (width, height)
        if self.channel:
            self.channel.resize_pty(width=width, height=height)
    
    def send_signal(self, sig: int) -> bool:
        """Send a signal to the remote PTY session"""
        if not self.channel or not self.channel.active:
            return False
            
        try:
            if sig in self.SIGNAL_MAP:
                self.channel.send(self.SIGNAL_MAP[sig])
                return True
            else:
                logger.warning(f"Unsupported signal: {sig}")
                return False
        except Exception as e:
            logger.error(f"Failed to send signal {sig}: {e}")
            return False
    
    def read_with_timeout(self, timeout: float = 0.5) -> str:
        """Read from PTY with timeout to prevent blocking"""
        if not self.channel:
            return ""
            
        response = ""
        end_time = time.time() + timeout
        
        while time.time() < end_time:
            if self.channel.recv_ready():
                chunk = self.channel.recv(1024).decode(errors='replace')
                if not chunk:  # Connection closed
                    break
                response += chunk
                # Reset timeout after receiving data to allow for more data
                end_time = time.time() + 0.1  # Short extension for more chunks
            else:
                # Small sleep to prevent CPU spinning
                time.sleep(0.01)
                
        return response
    
    def send_command(self, command: str) -> str:
        """Send a command to the PTY and read response"""
        if not self.channel or not self.channel.active:
            return "Error: Channel not active"
            
        try:
            # Ensure command has proper line ending
            command = command.rstrip('\n') + '\n'
            self.channel.send(command)
            
            # Read response with timeout
            return self.read_with_timeout()
            
        except Exception as e:
            logger.error(f"PTY command error: {e}")
            raise

class ClientSession:
    """Represents a connected client session"""
    
    def __init__(self, channel, client_info: str, addr: Tuple[str, int], 
                 transport_type: str, config: dict,
                 pty_enabled: bool = False, term_settings: Dict = None):
        self.id = str(uuid.uuid4())
        self.channel = channel
        self.transport = channel.get_transport()
        self.client_info = client_info
        self.addr = addr
        self.is_active = True
        self.transport_type = transport_type
        self.config = config
        self.hostname = None
        self.pty_enabled = pty_enabled
        self.term_settings = term_settings or {}
        self.username = None
        self.os_type = None
        self.connect_time = time.time()
        self.last_seen = time.time()
        self.capabilities = []
        self._parse_client_info()
        
        # Initialize PTY handler if PTY is enabled
        self.pty_handler = None
        if self.pty_enabled and self.channel:
            self.pty_handler = PTYHandler(self.channel)
            self.pty_handler.set_terminal_settings(
                term_type=self.term_settings.get('term', 'xterm'),
                width=self.term_settings.get('width', 80),
                height=self.term_settings.get('height', 24)
            )
    
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
            if self.pty_handler:
                self.pty_handler.set_terminal_settings(
                    term_type=self.term_settings.get('term', 'xterm'),
                    width=width,
                    height=height
                )
            else:
                self.channel.resize_pty(width=width, height=height)
                
            self.term_settings['width'] = width
            self.term_settings['height'] = height
            logger.debug(f"Resized PTY to {width}x{height}")
            return True
        except Exception as e:
            logger.error(f"Failed to resize PTY: {e}")
            return False
            
    def send_signal(self, sig: int) -> bool:
        """Send a signal to the client session"""
        if not self.pty_enabled:
            return False
            
        if self.pty_handler:
            return self.pty_handler.send_signal(sig)
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
            else:
                return f"Error: Unsupported transport type: {self.transport_type}"
        except Exception as e:
            logger.error(f"Error sending command: {e}")
            self.is_active = False
            return f"Error: {str(e)}"
    
    def _send_ssh_command(self, command: str) -> str:
        try:
            if not self.channel or not self.channel.active:
                raise Exception("Channel not active")

            if self.pty_enabled:
                # For empty input, send a newline character
                command = '\r\n' if command == '' else (command.rstrip('\n') + '\r\n')
                self.channel.send(command.encode())
                
                response = ''
                max_wait = 1.0  # Longer initial timeout
                start_time = time.time()
                
                while time.time() - start_time < max_wait:
                    if self.channel.recv_ready():
                        chunk = self.channel.recv(1024).decode(errors='replace')
                        response += chunk
                        # Extend timeout when receiving data
                        max_wait = time.time() - start_time + 0.2
                    else:
                        time.sleep(0.05)
                
                self.update_last_seen()
                return response
            else:
                # Non-PTY mode
                self.channel.send(command.encode())
                response = self.channel.recv(16384).decode(errors='replace')
                self.update_last_seen()
                return response
                
        except Exception as e:
            logger.error(f"SSH command error: {e}")
            self.is_active = False
            raise
    
    def handle_signal(self, sig: int) -> bool:
        """Handle signals like Ctrl+C by sending to remote session"""
        if not self.is_active or not self.channel or not self.channel.active:
            return False
            
        try:
            if sig == signal.SIGINT:  # Ctrl+C
                self.channel.send(b'\x03')
                return True
            elif sig == signal.SIGTSTP:  # Ctrl+Z
                self.channel.send(b'\x1a')
                return True
            elif sig == signal.SIGQUIT:  # Ctrl+\
                self.channel.send(b'\x1c')
                return True
            elif sig == signal.SIGTERM:  # Terminate
                self.channel.send(b'\x04')  # Ctrl+D / EOF
                return True
            else:
                logger.warning(f"Unsupported signal for client: {sig}")
                return False
        except Exception as e:
            logger.error(f"Error handling signal {sig}: {e}")
            return False
    
    def __str__(self):
        return f"{self.username}@{self.hostname} ({self.addr[0]}:{self.addr[1]}) [{self.transport_type}]"