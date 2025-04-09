from abc import ABC, abstractmethod
import logging
from typing import Dict, Optional, List, Callable
import threading
import time

from ..session.client_session import ClientSession

logger = logging.getLogger('c2.server')

class BaseServer(ABC):
    """Base class for C2 server transport implementations"""
    
    def __init__(self, config: dict, client_connected_callback: Callable = None):
        self.config = config
        self.clients: Dict[str, ClientSession] = {}
        self.running = False
        self.server_thread = None
        self.client_connected_callback = client_connected_callback
        
    @abstractmethod
    def start(self) -> None:
        """Start the server"""
        pass
        
    @abstractmethod
    def stop(self) -> None:
        """Stop the server"""
        pass
    
    def add_client(self, client: ClientSession) -> None:
        """Register a new client"""
        self.clients[client.id] = client
        logger.info(f"New client registered: {client}")
        
        # Notify the callback if registered
        if self.client_connected_callback:
            self.client_connected_callback(client)
            
    def remove_client(self, client_id: str) -> None:
        """Remove a client"""
        if client_id in self.clients:
            client = self.clients[client_id]
            logger.info(f"Client removed: {client}")
            del self.clients[client_id]
            
    def get_client(self, client_id: str) -> Optional[ClientSession]:
        """Get a client by ID"""
        return self.clients.get(client_id)
            
    def get_clients(self) -> List[ClientSession]:
        """Get all clients"""
        return list(self.clients.values())
            
    def get_active_clients(self) -> List[ClientSession]:
        """Get all active clients"""
        return [client for client in self.clients.values() if client.is_active]
    
    def cleanup_inactive_clients(self, max_age: int = 3600) -> None:
        """Remove inactive clients that haven't been seen in a while"""
        current_time = time.time()
        to_remove = []
        
        for client_id, client in self.clients.items():
            if not client.is_active and (current_time - client.last_seen) > max_age:
                to_remove.append(client_id)
                
        for client_id in to_remove:
            self.remove_client(client_id)
            
        if to_remove:
            logger.info(f"Cleaned up {len(to_remove)} inactive clients")