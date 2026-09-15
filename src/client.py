import socket
import sys
import argparse
import os
from secure_node import SecureNODE


def start_client(arg_host, arg_port):
    host = arg_host
    port = arg_port
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
        aes_key_str = aes_key.hex()
        NODE.pack_and_encrypt(aes_key_str)
        print("[+] AES key established for this session...sending now")
        print("Starting Chat")

        try:
            while True:

                #--------message send--------
                message = input("[YOU]: ")
                if not message:
                    continue
                NODE.aes_pack_and_encrypt(message, aes_key)

                #--------message recieve--------
                data_recv = NODE.aes_unpack_and_decrypt(aes_key)
                if not data_recv:
                    print("\n[-] Server disconnected.")
                    break
                print(f"[Server]: {data_recv}")

        except KeyboardInterrupt:
            print("\n[!] keyboard interrupt detected. exiting now...")

        except ConnectionResetError:
            print("\n[-] connection closed by client. exiting...")

    print("[*] Connection closed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Babel-TCP Secure Client Node")
    parser.add_argument("--host", default="127.0.0.1", help="IP address to bind to")
    parser.add_argument("--port", type=int, default=65432, help="Port to listen on")

    args = parser.parse_args()
    os.system('cls' if os.name == 'nt' else 'clear')
    start_client(args.host, args.port)
