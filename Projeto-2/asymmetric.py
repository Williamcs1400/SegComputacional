import random

class AsymKey:
  def __init__(self, bits = 1024):
    self.bits = bits

  def generateRandomPrime(self):
    while(True):
        # faz OR com 0x01 (1 no bit menos significativo) 
        #           para garantir que eh um número impar
        # faz OR com 0x01 << 1024 (bit mais significativo)
        #           para garantir que cabe em 1024
        ranPrime = random.getrandbits(self.bits) | (1 << (self.bits-1)) | 1
        if self.isPrime(ranPrime):
            return ranPrime

  # verifica se um numero eh primo
  # utilizando o teste de miller-rabin
  # https://medium.com/@prudywsh/how-to-generate-big-prime-numbers-miller-rabin-49e6e6af32fb
  def isPrime(self, number):
      if number == 2 or number == 3:
          return True

      if number < 2 or number % 2 == 0:
          return False

      s = 0
      r = number-1

      while r & 1 == 0:
          s += 1
          r //= 2
      
      for _ in range(128):
          a = random.randrange(2, number-1)
          x = pow(a, r, number)
          if x != 1 and x != number-1:
              j = 1
              while j < s and x != number-1:
                  x = pow(x, 2, number)
                  if x == 1:
                      return False
                  j += 1
              if x != number-1:
                  return False

      return True

  # inverso multiplicativo modular
  # utilizando algoritmo de euclides estendido
  # https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
  def modInverse(self, a, b):
      t, newt = 0, 1
      r, newr = b, a

      while newr != 0:
          quotient = r // newr
          t, newt = newt, t - quotient * newt
          r, newr = newr, r - quotient * newr

      if t < 0:
          t = t + b

      return t

  # calcular mdc
  def mdc(self, a, b): 
      while b != 0:
          a, b = b, a % b
      return a

  # Gerar chaves privadas com e phi e n
  def generatePrivateKey(self, e, phi, n):
      d = self.modInverse(e, phi)
      
      # faz d ser positivo
      d = d % phi
      if(d < 0):
          d += phi
          
      return (d,n)

  def generate(self):
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
    return (publicKey, privateKey)

class RSA:
  def __init__(self):
    pass

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