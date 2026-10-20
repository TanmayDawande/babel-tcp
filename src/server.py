import socket
import argparse
import os
from secure_node import SecureNODE
import asyncio
import chat_loop as cl

remote_name = "Client"

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
        #prevents address already use error when starting server quickly
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
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

                asyncio.run(cl.chat_subroutine(NODE, aes_key, remote_name))
            except KeyboardInterrupt:
                print("\n[!] Keyboard interrupt. Exiting now...")

    print("[*] Connection Closed")



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Babel-TCP Secure Server Node")
    parser.add_argument("--host", default="127.0.0.1", help="IP address to bind to")
    parser.add_argument("--port", type=int, default=65432, help="Port to listen on")

    args = parser.parse_args()

    os.system('cls' if os.name == 'nt' else 'clear')
    start_server(args.host, args.port)