import socket
import argparse
from random import randrange
from DH import DiffieHellman, primes, BUFFER_SIZE, asn_encoder, dec
from Handler import recive_message, send_message
from _thread import start_new_thread

SECRET_KEY = 0

def start_client():
    # Получение IP-адреса и порта из аргуметов командной строки
    ConnectionInfo = argparse.ArgumentParser()
    ConnectionInfo.add_argument("-ip", default = socket.gethostname())
    ConnectionInfo.add_argument("-p", type = int, default = '8080')
    ConnectionInfoParsed = ConnectionInfo.parse_args()
    IP = ConnectionInfoParsed.ip
    PORT = ConnectionInfoParsed.p
    
    # Создание объекта сокета: socket.AF_INET — для сокета используется IPv4, socket.SOCK_STREAM — тип сокета.
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print ("[ Socket created ]")
    
    # Связывание сокета с адресом и портом сервера
    print(f"[ Connecting to {IP}:{PORT} ]")
    client_socket.connect((IP, PORT))
    print("[ Connected ]")
    
    return client_socket

def keys_exchange(sock: socket):
    print("[ Waiting for key exchange to be initiated ]")
    msg = sock.recv(BUFFER_SIZE).decode("utf-8")
    if msg == "KEYEXCHANGE:READY":
        print("[ Key exchange started ]")
        
        # Выбор параметров группы и закрытого показателя
        rand =  int(sock.recv(BUFFER_SIZE).decode("utf-8"))
        if rand in primes:
            r = primes[rand]["prime"]
            a = primes[rand]["generator"]
            x = randrange (2, r)
        else:
            raise Exception("[ Group not supported ]")
        
        # Вычисление открытого ключа клиента
        cli = DiffieHellman("Client", x, a, r)
        cli.calculatePublicKey()
        
        print("[ Sending public key for server ]")
        data = asn_encoder(cli.getPublicKey(), a, r)
        sock.send(data)

        print("[ Waiting for server key ]")
        data = sock.recv(BUFFER_SIZE)
        with open("client.asn1", "wb") as file:
            file.write(data)
        param = dec(data)
        server_public_key = param[2]
        print("[ Received server key ]")
        
        # Вычисление секретного ключа
        print("[ Generating secret key ]")
        cli.setPublicKey(server_public_key)
        cli.calculatePrivateKey()
        SECRET_KEY = cli.privateKey

    else:
        print("[ Key exchange error ]")

if __name__ == "__main__":
    
    sock = start_client()
    
    # Обмен ключами
    keys_exchange(sock)
    
    # Обработка входящих сообщений
    print("[ Handling incoming messages ]")
    start_new_thread(recive_message, (sock, socket.gethostname(), SECRET_KEY))
    send_message(sock, SECRET_KEY)
    
    # Закрытие соединения
    sock.close()