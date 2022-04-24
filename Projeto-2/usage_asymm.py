# Segurança Computacional - UnB
from asymmetric import RSA, AsymKey

import base64

def main():
    asym_keygen = AsymKey()
    publicKey, privateKey = asym_keygen.generate()

    print('Chaves publicas: ', publicKey)
    print('Chaves privadas: ', privateKey)

    # Encriptar
    # with open("message.txt", "r") as f:
    #     message = f.read()
    message = "hello"
    
    rsa = RSA()
    cipherText = rsa.encrypt(message, publicKey)
    print('\nTexto cifrado: ', base64.b64encode(cipherText))

    # Decriptar
    decryptedText = rsa.decrypt(cipherText, privateKey)
    print('\nTexto decifrado: ', decryptedText)
      
if __name__ == '__main__':
    main()