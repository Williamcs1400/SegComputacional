# Segurança Computacional - UnB
from asymmetric import RSA, AsymKey

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
    cipherText = rsa.encrypt(message, privateKey)
    print('\nTexto cifrado: ', cipherText)

    # Decriptar
    decryptedText = rsa.decrypt(cipherText, publicKey)
    print('\nTexto decifrado: ', decryptedText)
      
if __name__ == '__main__':
    main()