import numpy as np

def cipher(plaintext, key):
    # Corrige key, se necessario
    builderKey = mendKey(key, len(plaintext))

    ciphertext = []
    for i in range(len(plaintext)):
        # ord() retorna a posicao na tabela ascii 
        # para cada posicao da string somamos o codigo ascii e fazemos % 26 
        # e somamos com ord(a) = '65'
        # assim garantimos que o texto cifrado sempre vai estar dentro do alfabeto
        builder = (ord(plaintext[i]) + ord(builderKey[i])) % 26
        builder += ord('A')
        ciphertext.append(chr(builder))
    return("".join(ciphertext))

def mendKey(key, size):
    if(len(key) == size):
        return key
    else:
        aux = 0
        keyBuilder = ''
        for i in range(size):
            keyBuilder += key[aux]
            aux += 1
            if aux == len(key):
                aux = 0
        return keyBuilder

def main():
    print('======== Cifrador ========')
    plaintext = input("Digite a mensagem a ser cifrada: ") 
    key = input("Agora digite a chave para cifrá-la: ")
    print(cipher(plaintext, key))


if __name__ == "__main__":
    main()