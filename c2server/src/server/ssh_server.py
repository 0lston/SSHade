import paramiko
import socket
import logging
import threading
import os
from typing import Tuple, Callable

from ..session.client_session import ClientSession
from .base_server import BaseServer

logger = logging.getLogger('c2.ssh')

class SSHServerInterface(paramiko.ServerInterface):
    """SSH Server Interface implementation"""
    
    def __init__(self, config: dict):
        self.config = config
        
    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_auth_password(self, username, password):
        if (username == self.config['username'] and 
            password == self.config['password']):
            return paramiko.AUTH_SUCCESSFUL
        logger.warning(f"Authentication failed for user: {username}")
        return paramiko.AUTH_FAILED
        
    def get_allowed_auths(self, username):
        return 'password'


class SSHServer(BaseServer):
    """SSH transport implementation for C2 server"""
    
    def __init__(self, config: dict, client_connected_callback: Callable = None):
        super().__init__(config, client_connected_callback)
        self.server_socket = None
        self.host_key = None
        self._load_host_key()
        
    def _load_host_key(self):
        """Load the SSH host key, create if not exists"""
        key_path = self.config['host_key']
        
        try:
            if not os.path.exists(key_path):
                # Generate a new key if one doesn't exist
                logger.info(f"Generating new host key at {key_path}")
                key_dir = os.path.dirname(key_path)
                if key_dir and not os.path.exists(key_dir):
                    os.makedirs(key_dir, exist_ok=True)
                key = paramiko.RSAKey.generate(2048)
                key.write_private_key_file(key_path)
                self.host_key = key
            else:
                self.host_key = paramiko.RSAKey(filename=key_path)
                
            logger.info(f"Loaded host key from {key_path}")
        except Exception as e:
            logger.error(f"Failed to load host key: {e}")
            raise
    
    def start(self):
        """Start the SSH server"""
        if self.running:
            logger.warning("SSH server already running")
            return
            
        try:
            # Create server socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config['bind_address'], self.config['ssh_port']))
            self.server_socket.listen(5)
            
            self.running = True
            logger.info(f"SSH server listening on {self.config['bind_address']}:{self.config['ssh_port']}")
            
            self.server_thread = threading.Thread(target=self._accept_connections)
            self.server_thread.daemon = True
            self.server_thread.start()
            
        except Exception as e:
            logger.error(f"Failed to start SSH server: {e}")
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            raise
    
    def stop(self):
        """Stop the SSH server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        logger.info("SSH server stopped")
    
    def _accept_connections(self):
        """Accept incoming connections"""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                threading.Thread(target=self._handle_connection, 
                              args=(client_socket, addr)).start()
            except OSError:
                if self.running:
                    logger.error("Error accepting connection")
            except Exception as e:
                if self.running:
                    logger.error(f"Error in accept loop: {e}")
    
    def _handle_connection(self, client_socket, addr: Tuple[str, int]):
        """Handle a new client connection"""
        logger.info(f"New SSH connection from {addr[0]}:{addr[1]}")
        
        try:
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            
            server_interface = SSHServerInterface(self.config)
            transport.start_server(server=server_interface)
            
            channel = transport.accept(20)
            if channel is None:
                logger.error(f"No channel established from {addr[0]}:{addr[1]}")
                return
            
            # Receive client info
            client_info = channel.recv(1024).decode(errors='replace')
            logger.info(f"Client info received: {client_info}")
            
            # Create a new client session
            client = ClientSession(channel, client_info, addr, 'ssh')
            
            # Register the client
            self.add_client(client)
            
            # Send acknowledgment
            channel.send(' ')
            
        except Exception as e:
            logger.error(f"Error handling connection: {e}")