import paramiko
from typing import Dict, Optional, List, Any
import logging
import time
import os

logger = logging.getLogger('SFTPClient')

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

