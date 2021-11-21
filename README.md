# Diffie-Hellman-key-establishment-protocol

Протокол установления ключа Диффи-Хеллмана.

Передача данных производиться посредством сетевого взаимодействия сторон. <br />
Сначала выполняется запуск сервера, который прослушивает указанный порт на указанном ip-адресе (по умолчанию – localhost:8080). <br />
При подключении клиента сервер отправляя служебное сообщение инициализирует процесс обмена ключами. <br />
Параметры криптосистемы выбираются случайно из заданного набора значений. <br />
После установления секретного ключа клиент и сервер могут обмениваться сообщениями, которые шифруются алгоритмом AES-256 в режиме CBC. 