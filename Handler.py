from AES import AESCipher
import socket

BUFFER_SIZE = 4096

def recive_message(sock: socket, addr: str, secret: int) -> None:
    while True:
        try:
            msg = sock.recv(BUFFER_SIZE)
            msg = AESCipher(msg, str(secret)).decrypt()
            if not msg:
                break
            print(f"\r{addr} : {msg}")
            print("\r> ", end="")
        except socket.error:
            print("[ ERROR: Could not recive message ]")
            break
        except ValueError:
            break

    print(f"[ Connection with {addr} closed ]\n")
    sock.close()   
    
def send_message(sock: socket, secret: int) -> None:
    while True:
        msg = input("> ")
        if not msg:
            break
        encrypt_client = AESCipher(msg, str(secret)).encrypt()
        try:
            sock.sendall(encrypt_client)
        except socket.error:
            print("[ ERROR: Could not send message ]")
            break
        
    print(f"[ Connection closed ]\n")
    sock.close()

def recieve(sock: socket) -> str:
    msg = sock.recv(BUFFER_SIZE).decode("utf-8")
    return msg