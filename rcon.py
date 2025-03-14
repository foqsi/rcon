import socket
import os
import argparse
from dotenv import load_dotenv

load_dotenv()

class RconClient:
    """
    Python RCON Client to connect and send commands to The Isle Evrima game server.
    """

    command_byte_map = {
        'announce': 0x10,
        'directmessage': 0x11,
        'serverdetails': 0x12,
        'wipecorpses': 0x13,
        'updateplayables': 0x15,
        'ban': 0x20,
        'kick': 0x30,
        'playerlist': 0x40,
        'save': 0x50,
        'getplayerdata': 0x77,
        'togglewhitelist': 0x81,
        'addwhitelist': 0x82,
        'removewhitelist': 0x83,
        'toggleglobalchat': 0x84,
        'togglehumans': 0x86,
        'toggleai': 0x90,
        'disableaiclasses': 0x91,
        'aidensity': 0x92,
    }

    def __init__(self, host=None, port=None, password=None, timeout=5):
        """
        Initializes the RCON client.
        If no arguments are provided, loads from environment variables.
        """
        self.host = host or os.getenv("SERVER_IP")
        self.port = int(port or os.getenv("RCON_PORT",))
        self.password = password or os.getenv("RCON_PW")
        self.timeout = timeout
        self.socket = None
        self.is_authorized = False

    def connect(self):
        """Establishes a connection to the server with error handling."""
        if not self.host or not self.port or not self.password:
            print("❌ RCON credentials missing! Set SERVER_IP, RCON_PORT, and RCON_PW in .env")
            return False

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.timeout)

        try:
            self.socket.connect((self.host, self.port))
            print(f"✅ Connected to RCON server")
            return self.authorize()
        except (socket.error, TimeoutError) as e:
            print(f"❌ Connection failed: {e}. Retrying in 30 seconds...")
            self.socket = None
            return False

    def authorize(self):
        """Authenticates the RCON session with the server."""
        if self.is_authorized:
            return True

        try:
            login_packet = b'\x01' + self.password.encode() + b'\x00'
            self.send_packet(login_packet)
            response = self.read_packet()

            if not response or "Timeout" in response:
                print("❌ Authentication timeout. Server did not respond.")
                return False
            elif "Accepted" in response or "Password Accepted" in response:
                print("✅ Authentication successful.")
                self.is_authorized = True
                return True
            else:
                print(f"❌ Authentication failed. Server response: {response}")
                return False
        except (socket.error, TimeoutError) as e:
            print(f"❌ Authorization failed: {e}")
            return False

    def disconnect(self):
        """Closes the socket connection safely."""
        if self.socket:
            try:
                self.socket.close()
                print("🔴 Disconnected from RCON server.")
            except socket.error as e:
                print(f"⚠️ Error disconnecting: {e}")
            finally:
                self.socket = None
                self.is_authorized = False

    def send_packet(self, data):
        """Sends raw data packets to the server with error handling."""
        if not self.socket:
            print("⚠️ No active RCON connection. Cannot send packet.")
            return

        try:
            self.socket.sendall(data)
        except (socket.error, TimeoutError) as e:
            print(f"❌ Failed to send packet: {e}")
            self.disconnect()

    def read_packet(self):
        """Receives the server's response safely."""
        if not self.socket:
            return "⚠️ No active connection to read from."

        try:
            response = self.socket.recv(4096)
            return response.decode('utf-8', errors='ignore')
        except socket.timeout:
            return "⚠️ Timeout: No response received."
        except socket.error as e:
            return f"❌ Socket error: {e}"

    def send_command(self, command_name, command_data=""):
        """
        Sends a mapped command to the server safely.
        - command_name: The name of the command (e.g., 'announce', 'kick', 'ban')
        - command_data: Additional data for the command (e.g., message, player ID)
        """
        if command_name not in self.command_byte_map:
            return f"❌ Unknown command: {command_name}"

        # Ensure connection before sending command
        if not self.socket or not self.is_authorized:
            print("🔄 Attempting to reconnect to RCON server...")
            if not self.connect():
                return "❌ Cannot send command. Failed to reconnect."

        command_byte = self.command_byte_map[command_name]
        command_packet = b'\x02' + bytes([command_byte]) + command_data.encode() + b'\x00'

        print(f"🔹 Sending RCON command: {command_name}, {command_data}")

        self.send_packet(command_packet)
        response = self.read_packet()
        return response if response else f"{command_name} Command Sent."

def main():
    """Allows RCON to be run from the command line."""
    parser = argparse.ArgumentParser(description="The Isle Evrima RCON Client")
    parser.add_argument('--command', type=str, help='Command to execute (e.g., announce, kick, ban, save)', required=True)
    parser.add_argument('--arg', type=str, help='Additional argument for the command (e.g., message, player ID)', default="")

    args = parser.parse_args()

    # Initialize RCON client with environment variables
    rcon = RconClient()

    if rcon.connect():
        print(f"🔹 Sending RCON command: {args.command}")
        response = rcon.send_command(args.command.lower(), args.arg)
        print(f"🔹 Server Response:\n{response}")
        rcon.disconnect()
    else:
        print("❌ Failed to connect to RCON server.")

if __name__ == "__main__":
    main()
