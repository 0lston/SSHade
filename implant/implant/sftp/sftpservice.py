from .stub_sftp import StubServer, StubSFTPServer
from ..forwarding.forwarding_handler import PortForwardingManager
import paramiko
import os
import time

HOST_KEY = paramiko.RSAKey.generate(2048)
class SFTPService:
    """
    A class to provide SFTP service functionality.
    Uses the port forwarding manager for the underlying transport.
    """
    def __init__(self, forwarder: PortForwardingManager):
        self.forwarder = forwarder
        self.active_ports = set()

    def create_sftp_handler(self, channel):
        """Create a handler function for SFTP channels"""
        def handle_sftp_channel():
            t = paramiko.Transport(channel)
            t.add_server_key(HOST_KEY)
            StubSFTPServer.ROOT = os.getcwd()
            t.set_subsystem_handler('sftp', paramiko.SFTPServer, StubSFTPServer)
            server = StubServer()
            try:
                t.start_server(server=server)
                # serve until closed
                while t.is_active() and self.forwarder.running:
                    time.sleep(0.5)
            finally:
                t.close()
                
        return handle_sftp_channel

    def start_sftp_server(self, remote_port=3333):
        """Start SFTP server on the specified port"""
        # Use the correct method name from PortForwardingManager
        result = self.forwarder.start_remote_forwarding(
            remote_port, 
            self.create_sftp_handler
        )
        if result:
            self.active_ports.add(remote_port)
        return result

    def stop_sftp_server(self, remote_port=3333):
        """Stop SFTP server on the specified port"""
        # Use the correct method name from PortForwardingManager
        result = self.forwarder.stop_remote_forwarding(remote_port)
        if result and remote_port in self.active_ports:
            self.active_ports.remove(remote_port)
        return result

    def stop_all_servers(self):
        """Stop all SFTP servers"""
        ports = list(self.active_ports)
        for port in ports:
            self.stop_sftp_server(port)