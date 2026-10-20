import socket
import sys
import argparse
import os
from secure_node import SecureNODE
from datetime import datetime
import asyncio

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
            asyncio.run(chat_subroutine(NODE, aes_key))
        except KeyboardInterrupt:
            print("\n[!] Keyboard interrupt. Exiting now...")

    print("[*] Connection Closed")


async def send(aes_key, NODE):
#--------message send--------
    while True:
        try:
            message = await asyncio.to_thread(input, f"{GREEN}[YOU]:{RESET} ")
            if not message.strip():
                continue
            timestamp = datetime.now().strftime("%I:%M:%S %p")
            print(f"\033[A\r\033[K[{timestamp}]{GREEN} [YOU]: {RESET} {message}")
            await asyncio.to_thread(NODE.aes_pack_and_encrypt, message, aes_key)
        except (ConnectionResetError, ConnectionAbortedError):
            break
        except Exception as e:
            print(f"\n[-] Send error: {e}")
            break

async def recieve(aes_key, NODE):
    #--------message recieve--------
    while True:
        try: 
            data_recv = await asyncio.to_thread(NODE.aes_unpack_and_decrypt, aes_key)
            if not data_recv:
                print("\n[-] Server disconnected.")
                break
            timestamp = datetime.now().strftime("%I:%M:%S %p")
            print(f"\r[{timestamp}] {BLUE}[SERVER]:{RESET} {data_recv}\n{GREEN}[YOU]:{RESET} ", end="", flush=True)
        except (ConnectionResetError, ConnectionAbortedError):
            print("\n[-] Connection was forcibly closed by the remote host.")
            break
        except Exception as e:
            print(f"\n[-] Recieve error: {e}")
            break

async def chat_subroutine(NODE, aes_key):
    recv_task = asyncio.create_task(recieve(aes_key, NODE))
    send_task = asyncio.create_task(send(aes_key, NODE))

    done, pending = await asyncio.wait(
        [recv_task, send_task],
        return_when=asyncio.FIRST_COMPLETED
    )

    for task in pending:
        task.cancel()

    for task in done:
        exc = task.exception()
        if exc:
            raise exc



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Babel-TCP Secure Client Node")
    parser.add_argument("--host", default="127.0.0.1", help="IP address to bind to")
    parser.add_argument("--port", type=int, default=65432, help="Port to listen on")

    args = parser.parse_args()
    
    os.system('cls' if os.name == 'nt' else 'clear')
    start_client(args.host, args.port)