import socket
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

def start_server(arg_host, arg_port):
    host = arg_host
    port = arg_port

    print(ASCII_ART)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((host, port))
        server_socket.listen()
        print(f"[*] Started listening on {host} and port {port}")
        conn, addr = server_socket.accept()
        NODE = SecureNODE(conn)

        with conn:
            print(f"[+] Connected by {addr}")
            print("[*] Performing RSA Handshake...")
            NODE.recieveHandshake()
            NODE.sendHandshake()

            conn.sendall(b'1')
            print("[+] Server initialized its own keys and recieved client keys")
            print("[+] Sending ACK")

            #--------AES key exchange--------
            aes_key = NODE.unpack_and_decrypt()
            print("[*] AES key recieved... established secure session")
            print("\n=== Starting Chat ===\n")

            try:
                while True:

                    #--------message recieve--------
                    data_recv = NODE.aes_unpack_and_decrypt(aes_key)
                    if not data_recv:
                        print("\n[-] Client disconnected.")
                        break
                    timestamp = datetime.now().strftime("%I:%M:%S %p")
                    print(f"[{timestamp}] {BLUE}[CLIENT]: {RESET} {data_recv}")

                    #--------message send--------
                    
                    message = input(f"{GREEN}[YOU]: {RESET}")
                    timestamp = datetime.now().strftime("%I:%M:%S %p")
                    print(f"\033[A\r\033[K[{timestamp}]{GREEN} [YOU]: {RESET} {message}")
                    if not message:
                        continue
                    NODE.aes_pack_and_encrypt(message, aes_key)
                    
            except KeyboardInterrupt:
                print("\n[!] Keyboard interrupt. Exiting now...")

            except ConnectionResetError:
                print("\n[-] Connection was forcibly closed by the remote host")

    print("[*] Connection Closed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Babel-TCP Secure Server Node")
    parser.add_argument("--host", default="127.0.0.1", help="IP address to bind to")
    parser.add_argument("--port", type=int, default=65432, help="Port to listen on")

    args = parser.parse_args()

    os.system('cls' if os.name == 'nt' else 'clear')
    start_server(args.host, args.port)