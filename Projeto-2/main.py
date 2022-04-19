# Segurança Computacional - UnB
import random
bitsLength = 50

class KeysAndCipher:
    def __init__(self):
        pass

    def generateRandomPrime(self):
        while(True):
            ranPrime = random.getrandbits(bitsLength)
            if self.isPrime(ranPrime):
                return ranPrime

    # verifica se um numero eh primo
    def isPrime(self, number):
        # elimina os numeros pares para deixar o algaritmo mais eficiente
        if number == 2:
            return True
        if number < 2 or number % 2 == 0:
            return False

        for n in range(3, int(number**0.5) + 2, 2):
            if number % n == 0:
                return False
        return True

    # Inverso multiplicativo modular
    def modInverse(self, a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.modInverse(b % a, a)
            return (g, x - (b // a) * y, y)

    # calcular mdc
    def mdc(self, a, b): 
        while b != 0:
            a, b = b, a % b
        return a

    # Gerar chaves privadas com e phi e n
    def generatePrivateKey(self, e, phi, n):
        
        d = self.modInverse(e, phi)[1]
        
        # faz d ser positivo
        d = d % phi
        if(d < 0):
            d += phi
            
        return (d,n)

    # Cifracao simetrica AES modo CTR
    def encrypt(self, plainText, publicKey):
        # Separa o par em variaveis
        key, n = publicKey

        # Converte o texto para lista de numeros
        cipherText = []
        for char in plainText:
            cipherText.append(pow(ord(char),key,n))
        return cipherText

    def decrypt(self, cipherText, privateKey):
        key, n = privateKey
        plainText = []
        for num in cipherText:
            plainText.append(chr(pow(num,key,n)))
        return ''.join(plainText)

    def run(self, fileName):
        # Gerar primos aleatorios
        p = self.generateRandomPrime()
        q = self.generateRandomPrime()

        # definicoes de variaveis necessarias
        n = p * q
        phi = (p-1) * (q-1) # calculo do totiente de Euler
        e = random.randint(1, phi) # escolher um e entre 1 e phi que seja primo relativo a phi
        g = self.mdc(e,phi)
        while g != 1:
            e = random.randint(1, phi)
            g = self.mdc(e, phi)

        # Gerar chaves
        publicKey = (e,n)
        privateKey = self.generatePrivateKey(e, phi, n)

        print('Chaves publicas: ', publicKey)
        print('Chaves privadas: ', privateKey)

        # Encriptar
        with open(fileName, "r") as f:
            message = f.read()
        
        cipherText = self.encrypt(message, publicKey)
        print('\nTexto cifrado: ', cipherText)

        # Decriptar
        decryptedText = self.decrypt(cipherText, privateKey)
        print('\nTexto decifrado: ', decryptedText)

def main():
    KaC = KeysAndCipher()
    KaC.run("message.txt")
  
if __name__ == '__main__':
    main()