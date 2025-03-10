import socket
import sys
import os
import argparse

# Global configurations
ip = "127.0.0.1"
port = 8888
password = "password"
timeout = 5
arg = ""

def cls():
    """Clear the console screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


class RconClient:
    """
    RCON Client to connect and send commands to the game server.
    """
    def __init__(self, host, port, password, timeout=5):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.socket = None
        self.is_authorized = False

        # Command mapping (mimics PHP version)
        self.command_byte_map = {
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

    def connect(self):
        """Establish connection and authenticate."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.timeout)

        try:
            self.socket.connect((self.host, self.port))
            print("Connected to RCON server.")
            return self.authorize()
        except socket.error as e:
            print(f"Connection failed: {e}")
            return False

    def authorize(self):
        """Send authentication packet."""
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
        """Close the socket connection."""
        if self.socket:
            self.socket.close()
            self.socket = None
            self.is_authorized = False

    def send_packet(self, data):
        """Send raw data packet to the server."""
        try:
            self.socket.sendall(data)
        except socket.error as e:
            print(f"Failed to send packet: {e}")

    def read_packet(self):
        """Read response from the server."""
        try:
            response = self.socket.recv(4096)
            return response.decode('utf-8', errors='ignore')
        except socket.timeout:
            return "No response received."
        except socket.error as e:
            return f"Socket error: {e}"

    def send_command(self, command_name, command_data=""):
        """Send a mapped command to the server."""
        if command_name not in self.command_byte_map:
            return f"Unknown command: {command_name}"

        command_byte = self.command_byte_map[command_name]
        command_packet = b'\x02' + bytes([command_byte]) + command_data.encode() + b'\x00'
        
        self.send_packet(command_packet)
        response = self.read_packet()
        return response if response else f"{command_name} Command Sent."


# Function to handle CLI commands
def execute_command(client, command):
    """Execute an RCON command using the client."""
    if command == "save":
        print(client.send_command("save"))
    elif command == "announce":
        print(client.send_command("announce", arg))
    elif command == "ban":
        print(client.send_command("ban", arg))
    elif command == "kick":
        print(client.send_command("kick", arg))
    elif command == "list":
        print(client.send_command("playerlist"))
    else:
        print("Unknown command specified.")


def choose_command(client):
    """Interactive menu for executing RCON commands."""
    cls()
    print("Credit: Aspect#3735")
    print("Version: 0.2")

    while True:
        print("\nSelect a command:")
        print("1 - Save the Server")
        print("2 - Make an Announcement")
        print("3 - Ban a Player")
        print("4 - Kick a Player")
        print("5 - Display Player List")
        print("6 - Exit")

        try:
            choice = int(input("Enter your choice: "))
        except ValueError:
            print("Invalid choice. Please enter a number.")
            continue
        
        if choice == 1:
            print(client.send_command("save"))
        elif choice == 2:
            msg = input("Enter announcement message: ")
            print(client.send_command("announce", msg))
        elif choice == 3:
            ban_info = input("Enter ban details: ")
            print(client.send_command("ban", ban_info))
        elif choice == 4:
            kick_id = input("Enter player ID to kick: ")
            print(client.send_command("kick", kick_id))
        elif choice == 5:
            print(client.send_command("playerlist"))
        elif choice == 6:
            client.disconnect()
            sys.exit()
        else:
            print("Invalid choice, please try again.")


def connect():
    """Parse arguments, connect to RCON server, and execute a command if provided."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', type=str, help='Server IP address')
    parser.add_argument('--port', type=int, help='RCON port')
    parser.add_argument('--password', type=str, help='RCON password')
    parser.add_argument('--command', type=str, help='Command to execute')
    parser.add_argument('--arg', type=str, help='Additional argument (player ID, message, etc.)')

    args = parser.parse_args()
    global ip, port, password, arg
    
    if args.ip:
        ip = args.ip
        port = args.port or port
        password = args.password or password
        arg = args.arg or ""
    else:
        ip = input("Enter server IP (e.g., 155.11.23.55): ")
        port = int(input("Enter RCON port: "))
        password = input("Enter RCON password: ")

    client = RconClient(ip, port, password)

    if client.connect():
        if args.command:
            execute_command(client, args.command.lower())
        else:
            choose_command(client)
    else:
        print("Failed to connect to RCON server.")
        sys.exit()

    client.disconnect()


connect()
