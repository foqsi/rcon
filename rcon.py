import socket
import sys
import argparse

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
        'aidensity': 0x92
    }

    def __init__(self, host, port, password, timeout=5):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.socket = None
        self.is_authorized = False

    def connect(self):
        """Establishes a connection to the server."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.timeout)

        try:
            self.socket.connect((self.host, self.port))
            print(f"Connected to RCON server at {self.host}:{self.port}")
            return self.authorize()
        except socket.error as e:
            print(f"Connection failed: {e}")
            return False

    def authorize(self):
        """Authenticates the RCON session with the server."""
        if not self.is_authorized:
            login_packet = b'\x01' + self.password.encode() + b'\x00'
            self.send_packet(login_packet)
            response = self.read_packet()
            
            if "Accepted" not in response:
                print("Authentication failed.")
                return False

            print("Authentication successful.")
            self.is_authorized = True
        return True

    def disconnect(self):
        """Closes the socket connection."""
        if self.socket:
            self.socket.close()
            self.socket = None
            self.is_authorized = False
            print("Disconnected from RCON server.")

    def send_packet(self, data):
        """Sends raw data packets to the server."""
        try:
            self.socket.sendall(data)
        except socket.error as e:
            print(f"Failed to send packet: {e}")

    def read_packet(self):
        """Receives the server's response."""
        try:
            response = self.socket.recv(4096)
            return response.decode('utf-8', errors='ignore')
        except socket.timeout:
            return "No response received."
        except socket.error as e:
            return f"Socket error: {e}"

    def send_command(self, command_name, command_data=""):
        """
        Sends a mapped command to the server.
        - command_name: The name of the command (e.g., 'announce', 'kick', 'ban')
        - command_data: Additional data for the command (e.g., message, player ID)
        """
        if command_name not in self.command_byte_map:
            return f"Unknown command: {command_name}"

        command_byte = self.command_byte_map[command_name]
        command_packet = b'\x02' + bytes([command_byte]) + command_data.encode() + b'\x00'

        self.send_packet(command_packet)
        response = self.read_packet()
        return response if response else f"{command_name} Command Sent."

# Function to handle CLI commands
def execute_command(client, command, arg=""):
    """Executes a command based on user input."""
    print(client.send_command(command, arg))

def main():
    """Main function to handle CLI arguments and connect to the server."""
    parser = argparse.ArgumentParser(description="The Isle Evrima RCON Client")
    parser.add_argument('--ip', type=str, help='Server IP address', required=True)
    parser.add_argument('--port', type=int, help='RCON port', required=True)
    parser.add_argument('--password', type=str, help='RCON password', required=True)
    parser.add_argument('--command', type=str, help='Command to execute (e.g., announce, kick, ban, save)', required=True)
    parser.add_argument('--arg', type=str, help='Additional argument for the command (e.g., message, player ID)')

    args = parser.parse_args()

    client = RconClient(args.ip, args.port, args.password)

    if client.connect():
        execute_command(client, args.command.lower(), args.arg or "")
    else:
        print("Failed to connect to RCON server.")
        sys.exit()

    client.disconnect()

if __name__ == "__main__":
    main()
