from Crypto.Cipher import AES
from Crypto.Random import new as Random
from hashlib import sha256
from base64 import b64encode,b64decode
import asn1

iv = b'\x00' * AES.block_size

class AESCipher:
  def __init__(self, data, key):
    self.data = data
    self.block_size = AES.block_size
    self.key = sha256(key.encode()).digest()[:32]
    self.pad = lambda s: s + (self.block_size - len(s) % self.block_size) * chr (self.block_size - len(s) % self.block_size)
    self.unpad = lambda s: s[:-ord(s[len(s) - 1:])]

  def encrypt(self):
    # Создание нового шифра AES256-CBC  
    plain_text = self.pad(self.data)
    cipher = AES.new(self.key, AES.MODE_CBC, iv)
    # Шифрование, pad - дополнение неполного блока
    encrypttext = b64encode(iv + cipher.encrypt(plain_text.encode())).decode()
    # Преобразование в asn.1 формат
    asn1_text = asn_encoderAES(len(encrypttext), encrypttext)
    return asn1_text

  def decrypt(self):
    parameters = []
    text = self.data
    decoder = asn1.Decoder()
    # Начало декодирования
    decoder.start(text)
    asn_decoderAES(decoder, parameters)
    encrypttext = text[-parameters[-1]:]
    cipher_text = b64decode(encrypttext)
    
    # Создание нового шифра AES256-CBC  
    cipher = AES.new(self.key, AES.MODE_CBC, iv)
    # Расшифрование шифртекста, unpad - убирает дополнение неполного блока
    decrypted = self.unpad(cipher.decrypt(cipher_text[self.block_size:])).decode()

    return bytes(decrypted, 'utf-8')
    

def asn_encoderAES(lenth, encrypted):
    encoder = asn1.Encoder()
    # Начало кодирования
    encoder.start()
    # Основная последовательность
    encoder.enter(asn1.Numbers.Sequence)
    # Набор ключей 
    encoder.enter(asn1.Numbers.Set)
    
    # Последовательность -- первый ключ 
    encoder.enter(asn1.Numbers.Sequence)
    # Идентификатор AES
    encoder.write(b'0x1082', asn1.Numbers.OctetString)
    # Выход из множества ключа RSA
    encoder.leave()
    
    # Выход из набора ключей
    encoder.leave() 
    
    # Последовательность данных зашифрованного сообщеняи
    encoder.enter(asn1.Numbers.Sequence)
    # Длина шифротекста
    encoder.write(lenth, asn1.Numbers.Integer)
    # Запись шифртекста
    encoder.write(encrypted, asn1.Numbers.OctetString)
    # Выход из последовательности данных
    encoder.leave()
    
    # Выход из основной последовательности
    encoder.leave()
    
    return encoder.output()

def asn_decoderAES(decoder, parameters):
    while not decoder.eof():
        try:
            tag = decoder.peek()
            if tag.nr == asn1.Numbers.Null:
                break
            if tag.typ == asn1.Types.Primitive:
                tag, value = decoder.read()
                # Если тип Integer
                if tag.nr == asn1.Numbers.Integer: 
                    # Добавляем значение в массив
                    parameters.append(value)
            else:
                decoder.enter()
                asn_decoderAES(decoder, parameters)
                decoder.leave()

        except asn1.Error:
            break