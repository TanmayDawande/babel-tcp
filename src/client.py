import socket
import sys
import argparse
import os
from secure_node import SecureNODE
from datetime import datetime

GREEN = "\033[32m"
BLUE = "\033[34m"
RESET = "\033[0m"


ASCII_ART = """
▀█████████▄     ▄████████ ▀█████████▄     ▄████████  ▄█       
  ███    ███   ███    ███   ███    ███   ███    ███ ███       
  ███    ███   ███    ███   ███    ███   ███    █▀  ███       
 ▄███▄▄▄██▀    ███    ███  ▄███▄▄▄██▀   ▄███▄▄▄     ███       
▀▀███▀▀▀██▄  ▀███████████ ▀▀███▀▀▀██▄  ▀▀███▀▀▀     ███       
  ███    ██▄   ███    ███   ███    ██▄   ███    █▄  ███       
  ███    ███   ███    ███   ███    ███   ███    ███ ███▌    ▄ 
▄█████████▀    ███    █▀  ▄█████████▀    ██████████ █████▄▄██ 
                                                    ▀         
"""

def start_client(arg_host, arg_port):
    host = arg_host
    port = arg_port

    print(ASCII_ART)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            client_socket.connect((host, port))
        except ConnectionRefusedError:
            sys.exit("[-] Connection Refused. Is the Server running?")
        NODE = SecureNODE(client_socket)

        NODE.sendHandshake()
        NODE.recieveHandshake()

        print("[*] Waiting for ACK...") #ack after the client sends its keys.
        flag = client_socket.recv(1)
        if(flag == b'1'):
            print("[+] ACK recieved")
            print("[+] Starting AES key exchange")
        else:
            sys.exit("[-] Handshake failed exiting now...")

        #--------AES key exchange--------
        aes_key = os.urandom(32)
        NODE.pack_and_encrypt(aes_key)
        print("[+] AES key established for this session... sending now")
        print("\n=== Starting Chat ===\n")

        try:
            while True:

                #--------message send--------
                message = input(f"{GREEN}[YOU]: {RESET}")
                timestamp = datetime.now().strftime("%I:%M:%S %p")
                print(f"\033[A\r\033[K[{timestamp}]{GREEN} [YOU]:{RESET} {message}")
                if not message:
                    continue
                NODE.aes_pack_and_encrypt(message, aes_key)

                #--------message recieve--------
                data_recv = NODE.aes_unpack_and_decrypt(aes_key)
                if not data_recv:
                    print("\n[-] Server disconnected.")
                    break

                timestamp = datetime.now().strftime("%I:%M:%S %p")
                print(f"[{timestamp}]{BLUE} [SERVER]:{RESET} {data_recv}")

        except KeyboardInterrupt:
            print("\n[!] Keyboard interrupt detected. Exiting now...")

        except ConnectionResetError:
            print("\n[-] Connection closed by client. Exiting...")

    print("[*] Connection closed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Babel-TCP Secure Client Node")
    parser.add_argument("--host", default="127.0.0.1", help="IP address to bind to")
    parser.add_argument("--port", type=int, default=65432, help="Port to listen on")

    args = parser.parse_args()
    
    os.system('cls' if os.name == 'nt' else 'clear')
    start_client(args.host, args.port)