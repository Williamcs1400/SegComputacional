# Segurança Computacional - UnB
from asymmetric import RSA, AsymKey, OAEP
import binascii
import base64

def main():
    asym_keygen = AsymKey()
    publicKey, privateKey = asym_keygen.generate()

    print('--------------------------------------')
    print('Cifração assimétrica AES modo CTR')
    print('Chaves publicas: ', publicKey)
    print('Chaves privadas: ', privateKey)

    # # Encriptar
    with open("message.txt", "r") as f:
        message = f.read()
    
    rsa = RSA()
    cipherText = rsa.encrypt(message, publicKey)
    print('\nTexto cifrado: ', cipherText)

    # Decriptar
    decryptedText = rsa.decrypt(cipherText, privateKey)
    print('\nTexto decifrado: ', decryptedText)

    print('\n\n--------------------------------------')
    print('Cifração assimética OAEP')

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

if __name__ == '__main__':
    main()