import socket
import argparse
from random import randrange
from DH import DiffieHellman, primes, BUFFER_SIZE, asn_encoder, dec
from Handler import recive_message, send_message
from _thread import start_new_thread

SECRET_KEY = 0

def start_server():
    # Получение IP-адреса и порта из аргуметов командной строки
    ConnectionInfo = argparse.ArgumentParser()
    ConnectionInfo.add_argument("-ip", default = socket.gethostname())
    ConnectionInfo.add_argument("-p", type = int, default = '8080')
    ConnectionInfoParsed = ConnectionInfo.parse_args()
    IP = ConnectionInfoParsed.ip
    PORT = ConnectionInfoParsed.p
    
    # Создание объекта сокета: socket.AF_INET — для сокета используется IPv4, socket.SOCK_STREAM — тип сокета.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Связывание сокета с адресом и портом.
    server_socket.bind((IP, PORT))
    print (f"[ Socket bind complete ]")
    
    # Ожидание соединения клиента: 1 - максимальное количество подключений в очереди.
    server_socket.listen(1)

    print(f"[ Server is now listening on {IP}:{PORT} ]")

    return server_socket

def keys_exchange(sock: socket):
    
    print("[ Initiating key exchange with client ]")
    sock.send("KEYEXCHANGE:READY".encode("utf-8"))
    
    # Выбор параметров группы и закрытого показателя
    rand = randrange (1, 6)
    if rand in primes:
        r = primes[rand]["prime"]
        a = primes[rand]["generator"]
        y = randrange (2, r)
    else:
        raise Exception("[ Group not supported ]")
    sock.send(str(rand).encode("utf-8"))
    
    # Вычисление открытого ключа сервера
    serv = DiffieHellman("Server", y, a, r)
    serv.calculatePublicKey()
    
    print("[ Waiting for client public key ]")
    data = sock.recv(BUFFER_SIZE)
    with open("server.asn1", "wb") as file:
        file.write(data)
    if not data:
        print("[ Key exchange error ]")
        return
    param = dec(data)
    client_public_key = param[2]
    print("[ Received client key ]")
    
    print("[ Sending public key for client ]")
    data = asn_encoder(serv.getPublicKey(), a, r)
    sock.send(data)
    
    # Вычисление секретного ключа
    print("[ Generating secret key ]")
    serv.setPublicKey(client_public_key)
    serv.calculatePrivateKey()
    SECRET_KEY = serv.privateKey

if __name__ == "__main__":
    sock = start_server()
    
    # Установление соединения с клиентом - получение объекта клиентского сокета
    client_socket, client_addr = sock.accept()
    print(f'[ {client_addr} connected ]')
    
    # Обмен ключами
    keys_exchange(client_socket)
    
    # Обработка входящих сообщений
    print("[ Handling incoming messages ]")
    start_new_thread(recive_message, (client_socket, client_addr, SECRET_KEY))
    send_message(client_socket, SECRET_KEY)
    
    # Закрытие соединения
    client_socket.close()
    sock.close()