import socket
import argparse
import os
from secure_node import SecureNODE


def start_server(arg_host, arg_port):
    host = arg_host
    port = arg_port

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
            aes_key_string = NODE.unpack_and_decrypt()
            aes_key = bytes.fromhex(aes_key_string)
            print("[*] AES key recieved...established secure session")
            print("Starting Chat")

            try:
                while True:

                    #--------message recieve--------
                    data_recv = NODE.aes_unpack_and_decrypt(aes_key)
                    if not data_recv:
                        print("\n[-] Cient disconnected.")
                        break
                    print(f"[Client]: {data_recv}")

                    #--------message send--------
                    message = input("[YOU]: ")
                    if not message:
                        continue
                    NODE.aes_pack_and_encrypt(message, aes_key)
                    

            except KeyboardInterrupt:
                print("\n[!] keyboard interrupt. exiting now...")

            except ConnectionResetError:
                print("\n[-] connection was forcebly closed by the remote host")

    print("[*] Connection Closed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Babel-TCP Secure Server Node")
    parser.add_argument("--host", default="127.0.0.1", help="IP address to bind to")
    parser.add_argument("--port", type=int, default=65432, help="Port to listen on")

    args = parser.parse_args()

    os.system('cls' if os.name == 'nt' else 'clear')
    start_server(args.host, args.port)
