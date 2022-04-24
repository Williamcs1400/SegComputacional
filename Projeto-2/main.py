from symmetric import AES, SymKey
from asymmetric import RSA, AsymKey

import hashlib
import base64
class Receiver:
  def __init__(self):
      asym_keygen = AsymKey()
      self.public_key, self._private_key = asym_keygen.generate()

  def receive(self, formatted_hash, formatted_enc_message, formatted_enc_session_key, src_public_key):
    rsa = RSA()

    # 3. a
    parsed_enc_msg = base64.b64decode(formatted_enc_message)
    parsed_enc_session_key = base64.b64decode(formatted_enc_session_key)
    parsed_hash = base64.b64decode(formatted_hash)

    # decifrar chave de sessao
    session_key = rsa.decrypt(parsed_enc_session_key, self._private_key)
    aes = AES(session_key)

    # 3. b
    message = aes.decrypt(parsed_enc_msg)

    # 3. c
    msg_hash = hashlib.sha3_256(message).hexdigest()
    rcv_msg_hash = rsa.decrypt(parsed_hash, src_public_key)

    print("Mensagem recebida:", message.decode())
    print("Hash calculado:", msg_hash)
    print("Hash recebido:", rcv_msg_hash.decode())

class Transmitter:
  def __init__(self):
    asym_keygen = AsymKey()
    self.public_key, self._private_key = asym_keygen.generate()

  def transmit(self, message, dest_public_key):
    # 1. a, b
    session_key = SymKey.generate(128)
    aes = AES(session_key)
    rsa = RSA()

    # 1.c
    encripted_message = aes.encrypt(message)

    # 1.d - cifrar a chave de sessao usada no AES com a chave *publica*
    encripted_session_key = rsa.encrypt(session_key, dest_public_key)

    ########### Assinatura 

    # 2. a
    msg_hash = str.encode(hashlib.sha3_256(message).hexdigest())

    # 2. b - cifrar o hash da mensagem com a chave *privada*
    signed_hash = rsa.encrypt(msg_hash, self._private_key)

    # 2. c
    formatted_hash = base64.b64encode(signed_hash)
    formatted_enc_message = base64.b64encode(encripted_message)
    formatted_enc_session_key = base64.b64encode(encripted_session_key)

    return formatted_hash, formatted_enc_message, formatted_enc_session_key

def main():
  with open("message.txt", "r") as f:
    message = f.read()

  tr = Transmitter()
  rc = Receiver()

  print("Chaves geradas\n")
  
  formatted_hash, formatted_enc_message, formatted_enc_session_key = tr.transmit(message.encode(), rc.public_key)

  rc.receive(formatted_hash, formatted_enc_message, formatted_enc_session_key, tr.public_key)

if __name__ == "__main__":
  main()