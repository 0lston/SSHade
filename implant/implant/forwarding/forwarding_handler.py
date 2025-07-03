import socket
import threading
import time
import logging
import struct
from typing import Callable

class PortForwardingManager:
    """
    Manage port forwarding: remote-to-local, local-to-remote and dynamic (SOCKS5).
    """
    def __init__(self, transport, channel):
        self.transport = transport
        self.channel = channel
        # Now store (thread, stop_event) tuples for remote and dynamic
        # Store (thread, stop_event, server_sock) for local forwarding
        self.remote_forward_threads = {}  # port -> (thread, stop_event)
        self.local_forward_threads = {}   # port -> (thread, stop_event, server_sock)
        self.dynamic_threads = {}         # port -> (thread, stop_event, server_sock)
        self.running = True

    def start_remote_forwarding(self, remote_port: int, handler_factory: Callable) -> bool:
        if remote_port in self.remote_forward_threads:
            thread, stop_event = self.remote_forward_threads[remote_port]
            if thread.is_alive():
                self.channel.send(f"\r\nAlready forwarding remote port {remote_port}\r\n")
                return True

        try:
            self.transport.request_port_forward('', remote_port)
            logging.info(f"Requested remote port forwarding on port {remote_port}")
            self.channel.send(f"\r\nRemote forwarding started on port {remote_port}\r\n")
        except Exception as e:
            logging.error(f"Remote port forward request failed: {e}")
            self.channel.send(f"\r\nRemote port forwarding failed: {e}\r\n")
            return False

        stop_event = threading.Event()

        def accept_forwarded():
            while self.running and not stop_event.is_set():
                try:
                    chan = self.transport.accept(1)
                    if not chan:
                        continue
                    handler = handler_factory(chan)
                    t = threading.Thread(target=handler, daemon=True)
                    t.start()
                except Exception as e:
                    logging.error(f"Error in forwarding thread: {e}")
                    time.sleep(1)
            logging.info(f"Stopped accepting connections on remote port {remote_port}")

        thread = threading.Thread(target=accept_forwarded, daemon=True)
        self.remote_forward_threads[remote_port] = (thread, stop_event)
        thread.start()
        return True

    def stop_remote_forwarding(self, remote_port: int) -> bool:
        if remote_port not in self.remote_forward_threads:
            self.channel.send(f"\r\nNo remote forwarding active on port {remote_port}\r\n")
            return True
        try:
            self.transport.cancel_port_forward('', remote_port)
            self.channel.send(f"\r\nCancelled remote forwarding on port {remote_port}\r\n")
            thread, stop_event = self.remote_forward_threads[remote_port]
            stop_event.set()
            if thread.is_alive():
                thread.join(2)
            del self.remote_forward_threads[remote_port]
            return True
        except Exception as e:
            logging.error(f"Cancel remote port forward failed: {e}")
            self.channel.send(f"\r\nError cancelling remote port forward: {e}\r\n")
            return False

    def start_local_forwarding(self, local_port: int, remote_host: str, remote_port: int) -> bool:
        """
        Classic -L: bind locally and forward to remote_host:remote_port over SSH.
        """
        if local_port in self.local_forward_threads:
            thread, stop_event, _ = self.local_forward_threads[local_port]
            if thread.is_alive():
                self.channel.send(f"\r\nAlready forwarding local port {local_port}\r\n")
                return True

        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(('0.0.0.0', local_port))
            server_sock.listen(5)
            server_sock.settimeout(1)
            logging.info(f"Listening on 127.0.0.1:{local_port}")
            self.channel.send(f"\r\nLocal forwarding started on 127.0.0.1:{local_port}\r\n")
        except Exception as e:
            logging.error(f"Failed to bind local port {local_port}: {e}")
            self.channel.send(f"\r\nLocal port forward setup failed: {e}\r\n")
            return False

        stop_event = threading.Event()

        def accept_loop():
            while self.running and not stop_event.is_set():
                try:
                    client_sock, addr = server_sock.accept()
                except socket.timeout:
                    continue
                except Exception as e:
                    logging.error(f"Accept error on {local_port}: {e}")
                    time.sleep(1)
                    continue

                logging.info(f"Accepted connection from {addr}")
                # open SSH channel
                try:
                    chan = self.transport.open_channel(
                        'direct-tcpip',
                        (remote_host, remote_port),
                        client_sock.getsockname()
                    )
                    if chan is None:
                        logging.error(f"SSH open_channel returned None for {remote_host}:{remote_port}")
                        client_sock.close()
                        continue
                except Exception as e:
                    logging.error(f"Failed to open SSH channel: {e}")
                    client_sock.close()
                    continue

                # handle data in separate thread
                threading.Thread(
                    target=self._bidirectional_forward,
                    args=(client_sock, chan),
                    daemon=True
                ).start()

            # cleanup
            server_sock.close()
            logging.info(f"Stopped local forwarding on port {local_port}")

        thread = threading.Thread(target=accept_loop, daemon=True)
        self.local_forward_threads[local_port] = (thread, stop_event, server_sock)
        thread.start()
        return True

    def stop_local_forwarding(self, local_port: int) -> bool:
        """
        Stop local forwarding on the given port.
        """
        if local_port not in self.local_forward_threads:
            self.channel.send(f"\r\nNo local forwarding active on port {local_port}\r\n")
            return True

        thread, stop_event, server_sock = self.local_forward_threads.pop(local_port)
        stop_event.set()
        # unblock accept
        try:
            dummy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            dummy.connect(('127.0.0.1', local_port))
            dummy.close()
        except Exception:
            pass

        if thread.is_alive():
            thread.join(timeout=2)
        self.channel.send(f"\r\nStopped local forwarding on port {local_port}\r\n")
        logging.info(f"Stopped local forwarding on port {local_port}")
        return True

    def start_dynamic_forwarding(self, listen_port: int) -> bool:
        if listen_port in self.dynamic_threads:
            thread, stop_event, _ = self.dynamic_threads[listen_port]
            if thread.is_alive():
                self.channel.send(f"\r\nSOCKS5 proxy already running on port {listen_port}\r\n")
                return True

        try:
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(('127.0.0.1', listen_port))
            server_sock.listen(5)
            server_sock.settimeout(1)
            logging.info(f"Started SOCKS5 proxy on port {listen_port}")
            self.channel.send(f"\r\nSOCKS5 proxy started on 127.0.0.1:{listen_port}\r\n")
        except Exception as e:
            logging.error(f"SOCKS5 proxy setup failed: {e}")
            self.channel.send(f"\r\nSOCKS5 proxy setup failed: {e}\r\n")
            return False

        stop_event = threading.Event()

        def accept_socks():
            try:
                while self.running and not stop_event.is_set():
                    try:
                        client_sock, addr = server_sock.accept()
                        logging.info(f"SOCKS connection from {addr[0]}:{addr[1]}")
                        threading.Thread(
                            target=self._handle_socks5_connection,
                            args=(client_sock,),
                            daemon=True
                        ).start()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        logging.error(f"Error accepting SOCKS connection: {e}")
                        if not self.running or stop_event.is_set():
                            break
                        time.sleep(1)
            finally:
                logging.info(f"Closing SOCKS5 proxy on port {listen_port}")
                try:
                    server_sock.close()
                except:
                    pass

        thread = threading.Thread(target=accept_socks, daemon=True)
        self.dynamic_threads[listen_port] = (thread, stop_event, server_sock)
        thread.start()
        return True

    def stop_dynamic_forwarding(self, listen_port: int) -> bool:
        if listen_port not in self.dynamic_threads:
            self.channel.send(f"\r\nNo SOCKS5 proxy active on port {listen_port}\r\n")
            return True
        try:
            thread, stop_event, server_sock = self.dynamic_threads.pop(listen_port)
            stop_event.set()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(('127.0.0.1', listen_port))
                s.close()
            except:
                pass
            if thread.is_alive():
                thread.join(2)
            self.channel.send(f"\r\nStopped SOCKS5 proxy on port {listen_port}\r\n")
            return True
        except Exception as e:
            logging.error(f"Stop SOCKS5 proxy failed: {e}")
            self.channel.send(f"\r\nError stopping SOCKS5 proxy: {e}\r\n")
            return False

    def _handle_socks5_connection(self, client_sock):
        """Handle a SOCKS5 client connection according to RFC 1928"""
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
        """
        # Forward client -> remote
        def forward_socket_to_channel():
            try:
                while self.running:
                    try:
                        data = client_socket.recv(4096)
                        if not data:
                            break
                        channel.send(data)
                    except Exception as e:
                        logging.debug(f"Socket to channel error: {e}")
                        break
            finally:
                try:
                    channel.close()
                except:
                    pass

        # Forward remote -> client
        def forward_channel_to_socket():
            try:
                while self.running:
                    try:
                        data = channel.recv(4096)
                        if not data:
                            break
                        client_socket.sendall(data)
                    except Exception as e:
                        logging.debug(f"Channel to socket error: {e}")
                        break
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
        self.running = False
        
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
            
    def start_remote_socks(self, remote_port: int) -> bool:
        """Start SOCKS5 proxy on a remote port"""
        def socks_handler_factory(channel):
            return lambda: self._handle_remote_socks(channel)
        
        return self.start_remote_forwarding(remote_port, socks_handler_factory)
    
    def _handle_remote_socks(self, channel):
        """Handle SOCKS5 connection from remote server"""
        try:
            # SOCKS5 handshake
            # 1. Authentication negotiation
            data = channel.recv(2)
            if len(data) < 2:
                logging.error("SOCKS5 handshake: too short")
                channel.close()
                return
                
            ver, nmethods = data[0], data[1]
            if ver != 5:  # SOCKS5
                logging.error(f"Unsupported SOCKS version: {ver}")
                channel.close()
                return
                
            # Read authentication methods
            methods = channel.recv(nmethods)
            
            # We only support no authentication (0)
            channel.send(b"\x05\x00")  # Ver=5, Method=0 (No auth)
            
            # 2. Command processing
            data = channel.recv(4)
            if len(data) < 4:
                logging.error("SOCKS5 request: too short")
                channel.close()
                return
                
            ver, cmd, rsv, atyp = data[0], data[1], data[2], data[3]
            if ver != 5:
                logging.error(f"Unexpected SOCKS version in request: {ver}")
                channel.close()
                return
                
            # We only support CONNECT command (1)
            if cmd != 1:
                logging.error(f"Unsupported SOCKS5 command: {cmd}")
                channel.send(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")  # Command not supported
                channel.close()
                return
                
            # Process address based on address type
            host = None
            if atyp == 1:  # IPv4
                addr_bytes = channel.recv(4)
                host = socket.inet_ntoa(addr_bytes)
            elif atyp == 3:  # Domain name
                length = channel.recv(1)[0]
                addr_bytes = channel.recv(length)
                host = addr_bytes.decode('utf-8')
            elif atyp == 4:  # IPv6
                addr_bytes = channel.recv(16)
                host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                logging.error(f"Unsupported address type: {atyp}")
                channel.send(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")  # Address type not supported
                channel.close()
                return
                
            # Read port (2 bytes, big endian)
            port_bytes = channel.recv(2)
            port = struct.unpack('!H', port_bytes)[0]
            
            logging.info(f"SOCKS5 CONNECT request for {host}:{port}")
            
            # Connect to the target
            try:
                target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_sock.settimeout(10)
                target_sock.connect((host, port))
                target_sock.settimeout(None)
                
                # Connection successful - send success response
                channel.send(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                
                # Start bidirectional forwarding
                self._bidirectional_forward(target_sock, channel)
            except Exception as e:
                logging.error(f"Error connecting to target: {e}")
                channel.send(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")  # Host unreachable
                channel.close()
        except Exception as e:
            logging.error(f"Error handling remote SOCKS connection: {e}")
            try:
                channel.close()
            except:
                pass