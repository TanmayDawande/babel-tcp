from datetime import datetime
import asyncio

GREEN = "\033[32m"
BLUE = "\033[34m"
RESET = "\033[0m"

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

async def recieve(aes_key, NODE, remote_name):
    #--------message recieve--------
    while True:
        try: 
            data_recv = await asyncio.to_thread(NODE.aes_unpack_and_decrypt, aes_key)
            if not data_recv:
                print(f"\n[-] {remote_name} disconnected.")
                break
            timestamp = datetime.now().strftime("%I:%M:%S %p")
            print(f"\r[{timestamp}] {BLUE}[{remote_name}]:{RESET} {data_recv}\n{GREEN}[YOU]:{RESET} ", end="", flush=True)
        except (ConnectionResetError, ConnectionAbortedError):
            print("\n[-] Connection was forcibly closed by the remote host.")
            break
        except Exception as e:
            print(f"\n[-] Recieve error: {e}")
            break

async def chat_subroutine(NODE, aes_key, remote):
    recv_task = asyncio.create_task(recieve(aes_key, NODE, remote))
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

