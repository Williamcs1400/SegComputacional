# Segurança Computacional - UnB
from symmetric import AES, SymKey
from asymmetric import RSA, AsymKey, OAEP
import base64
import hashlib

class Receiver:
  def __init__(self):
      asym_keygen = AsymKey()
      self.public_key, self._private_key = asym_keygen.generate()

  #def receive(self, formatted_hash, formatted_enc_message, formatted_enc_session_key, src_public_key):
  # Recebe as tres mensagens codificadas em Base64
  #   - msg_hash : Hash encriptado da mensagem
  #   - msg_ciphertext : Mensagem encriptada com chave de sessao
  #   - key_ciphertext : Chave de sessao encriptada
  #   - src_public_key : Chave publica do encriptador
  def receive(self, msg_hash, msg_ciphertext, key_ciphertext, src_public_key):
    rsa = RSA()

    # 3. a
    msg_hash = base64.b64decode(msg_hash)
    msg_ciphertext = base64.b64decode(msg_ciphertext)
    key_ciphertext = base64.b64decode(key_ciphertext)

    # decifrar chave de sessao
    session_key = rsa.decrypt(key_ciphertext, self._private_key)
    aes = AES(session_key)

    # 3. b
    message = aes.decrypt(msg_ciphertext)

    # 3. c
    calc_msg_hash = hashlib.sha3_256(message).hexdigest()
    rcv_msg_hash = rsa.decrypt(msg_hash, src_public_key)

    print("Mensagem recebida:", message.decode())
    print("Hash calculado:", calc_msg_hash)
    print("Hash recebido:", rcv_msg_hash.decode(), end="\n\n")

    if calc_msg_hash == rcv_msg_hash.decode():
      print("Hashs identicos. Mensagem recebida corretamente")
    else:
      print("Hashs distintos. Falha na transmissao da mensagem")

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
    msg_hash = hashlib.sha3_256(message).hexdigest().encode()

    # 2. b - cifrar o hash da mensagem com a chave *privada*
    signed_hash = rsa.encrypt(msg_hash, self._private_key)

    # 2. c
    msg_hash = base64.b64encode(signed_hash)
    msg_ciphertext = base64.b64encode(encripted_message)
    key_ciphertext = base64.b64encode(encripted_session_key)

    return msg_hash, msg_ciphertext, key_ciphertext

def main():
    with open("message.txt", "r") as f:
        message = f.read().encode()

    tr = Transmitter()
    rc = Receiver()

    print("Chaves geradas\n")

    msg_hash, msg_ciphertext, key_ciphertext = tr.transmit(message, rc.public_key)

    rc.receive(msg_hash, msg_ciphertext, key_ciphertext, tr.public_key)

    print('\n\n--------------------------------------')
    print('Cifração assimética OAEP')

    with open("message.txt", "r") as f:
        message = f.read()

    oaep = OAEP()
    publicKey, privateKey = oaep.generateKeys()
    print('Chaves publicas: ', publicKey)
    print('Chaves privadas: ', privateKey)

    s = oaep.createSignature(message, privateKey)
    enc = oaep.encryptRsaOaep(message.encode('utf-8'), publicKey)
    base64EncodedStr = base64.b64encode(enc)
    base64EncodedStrS = base64.b64encode(s)
    print('\nTexto cifrado em base64: ', base64EncodedStr.decode('utf-8'))
    print('\nAssinatura em base64: ', base64EncodedStrS.decode('utf-8'))

    # Decriptar
    decryptedText = oaep.decryptMessage(s, enc, publicKey, privateKey)
    print('\n\nTexto decifrado: ', decryptedText)
    print('\n\n')
if __name__ == "__main__":
  main()