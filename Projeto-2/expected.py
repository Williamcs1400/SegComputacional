# pip3 install PyCryptodome

from Crypto.Cipher import AES as LibAES, PKCS1_OAEP
from Crypto.Util import Counter as LibCounter
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA as LibRSA

import hashlib
import base64

class RSA:
  def __init__(self) -> None:
      pass

  def GenerateKeys(self):
    keys = LibRSA.generate(1024)
    private_key = keys.export_key()
    public_key = keys.publickey().export_key()
    return (public_key, private_key)

  def Encrypt(self, public_key, message):
    _key = LibRSA.importKey(public_key)
    cipher = PKCS1_OAEP.new(_key)
    return cipher.encrypt(message)

  def Decrypt(self, private_key, ciphertext):
    _key = LibRSA.importKey(private_key)
    cipher = PKCS1_OAEP.new(_key)
    return cipher.decrypt(ciphertext)


class AES:
  def __init__(self) -> None:
      pass

  def GenerateKey(self):
    return get_random_bytes(16)
  
  def Encrypt(self, message, key):
    obj = LibAES.new(key, LibAES.MODE_CTR, counter=LibCounter.new(128))
    return obj.encrypt(message)

  def Decrypt(self, ciphertext, key):
    obj = LibAES.new(key, LibAES.MODE_CTR, counter=LibCounter.new(128))
    return obj.decrypt(ciphertext)


class Receiver:
  def __init__(self):
      rsa = RSA()
      self.public_key, self._private_key = rsa.GenerateKeys()

  def receive(self, formatted_hash, formatted_enc_message, formatted_enc_session_key, src_public_key):
    aes = AES()
    rsa = RSA()

    # 3. a
    parsed_enc_msg = base64.b64decode(formatted_enc_message)
    parsed_enc_session_key = base64.b64decode(formatted_enc_session_key)
    parsed_hash = base64.b64decode(formatted_hash)

    # decifrar chave de sessao
    session_key = rsa.Decrypt(self._private_key, parsed_enc_session_key)

    # 3. b
    message = aes.Decrypt(parsed_enc_msg, session_key)

    # 3. c
    msg_hash = hashlib.sha3_256(message).hexdigest()
    # obs**:
    # rcv_msg_hash = rsa.Decrypt(src_public_key, parsed_hash) << essa parte nao funciona pq o OEAP nao permite encriptar com chave privada

    # print(msg_hash, rcv_msg_hash) << portanto, nao da pra ver se os hashes sao iguais aqui
    # mas todo o restante do processo ta certo, entao da pra printar o hash aqui e ver kek
    print(msg_hash)

class Transmitter:
  def __init__(self):
    rsa = RSA()
    self.public_key, self._private_key = rsa.GenerateKeys()

  def transmit(self, message, dest_public_key):
    rsa = RSA()
    aes = AES()
    # 1. a, b
    session_key = aes.GenerateKey()

    # 1.c
    encripted_message = aes.Encrypt(message, session_key)

    # 1.d - cifrar a chave de sessao usada no AES com a chave *publica*
    encripted_session_key = rsa.Encrypt(dest_public_key, session_key)

    ########### Assinatura 

    # 2. a
    msg_hash = str.encode(hashlib.sha3_256(message).hexdigest())
    print(msg_hash) # ver a obs** no receiver

    # 2. b - cifrar o hash da mensagem com a chave *privada*
    signed_hash = rsa.Encrypt(self._private_key, msg_hash)

    # 2. c
    formatted_hash = base64.b64encode(signed_hash)
    formatted_enc_message = base64.b64encode(encripted_message)
    formatted_enc_session_key = base64.b64encode(encripted_session_key)

    return formatted_hash, formatted_enc_message, formatted_enc_session_key

def main():
  message = b'hello darkness my old friend'
  tr = Transmitter()
  rc = Receiver()
  
  formatted_hash, formatted_enc_message, formatted_enc_session_key = tr.transmit(message, rc.public_key)

  rc.receive(formatted_hash, formatted_enc_message, formatted_enc_session_key, tr.public_key)

if __name__ == "__main__":
  main()