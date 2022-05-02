import random
from math import ceil
import hashlib as hl
import os
import base64
from typing import Tuple

class AsymKey:
  def __init__(self, bits = 1024):
    self.bits = bits

  def generateRandomPrime(self) -> int:
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
  def isPrime(self, number: int) -> bool:
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
  def modInverse(self, a: int, b: int) -> int:
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
  def mdc(self, a: int, b: int) -> int:
      while b != 0:
          a, b = b, a % b
      return a

  # Gerar chaves privadas com e phi e n
  def generatePrivateKey(self, e: int, phi: int, n: int) -> Tuple[int, int]:
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
    e = 0x010001#random.randint(1, phi) # escolher um e entre 1 e phi que seja primo relativo a phi
    g = self.mdc(e,phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = self.mdc(e, phi)

    # Gerar chaves
    publicKey = (e,n)
    privateKey = self.generatePrivateKey(e, phi, n)

    return (publicKey, privateKey)

class RSA:
  def __init__(self):
    pass

  def encrypt(self, plainText, publicKey: Tuple[int, int]) -> bytes:
    # Separa o par em variaveis
    key, n = publicKey

    # Verifica se o plainText eh um array de bytes
    if type(plainText) is str:
        plainText = plainText.encode()

    # Converte para inteiro e faz a exponenciacao
    if type(plainText) is bytes:
        plainText = int.from_bytes(plainText, 'big')

    exp = pow(plainText, key, n)

    # Retorna como array de bytes
    return exp.to_bytes((exp.bit_length() + 7) // 8, 'big')

  def decrypt(self, cipherText, privateKey: Tuple[int, int]) -> bytes:
    # Separa o par em variaveis
    key, n = privateKey

    # Verifica se o cipherText eh um array de bytes
    if type(cipherText) is str:
        cipherText = cipherText.encode()

    # Converte para inteiro e faz a exponenciacao
    if type(cipherText) is bytes:
        cipherText = int.from_bytes(cipherText, 'big')

    exp = pow(cipherText, key, n)

    return exp.to_bytes((exp.bit_length() + 7) // 8, 'big')

class OAEP:
    def __init__(self):
        # definição de e
        # self.e = 0x010001
        self.hlen = len(self.sha3(b''))

    # Converte um inteiro nao negativo em byteArray
    def i2osp(self, num, length):
        return num.to_bytes(length, "big")

    # Converte um byteArray em inteiro
    def os2ip(self, num):
        return int.from_bytes(num, byteorder='big')

    # Encripta uma mensagem com sha3
    def sha3(self, message):
        hasher = hl.sha3_512()
        hasher.update(message)
        return hasher.digest()

    # Gera assinatura da mensagem com sha3 - byteArray
    def createSignature(self, message, privateKey):
        e, n = privateKey
        return self.i2osp(pow(self.os2ip(self.sha3(message.encode("utf-8"))), e, n),256)

    # Gera mascara que sera usada para encriptar em OAEP
    # https://en.wikipedia.org/wiki/Mask_generation_function
    def mgf(self, z, l):
        assert l < (2**32)
        result = b""

        for i in range(ceil(l / self.hlen)):
            C = self.i2osp(i, 4)
            result += self.sha3(z + C)
        return result[:l]

    # Aplica mascara com um xor bit a bit
    def bitwiseXor(self, data, mask):
        masked = b''
        ldata = len(data)
        lmask = len(mask)
        for i in range(max(ldata, lmask)):
            if i < ldata and i < lmask:
                masked += (data[i] ^ mask[i]).to_bytes(1, byteorder='big')
            elif i < ldata:
                masked += data[i].to_bytes(1, byteorder='big')
            else:
                break
        return masked

    # Implementação do OAEP
    # https://stringfixer.com/pt/RSA-OAEP
    def oaepEncode(self, m, k, label=b''):
        mlen = len(m)
        lhash = self.sha3(label)
        ps = b'\x00' * (k - mlen - 2 * self.hlen - 2) # padding
        db = lhash + ps + b'\x01' + m
        seed = os.urandom(self.hlen) # gerar seed aleatorio para encriptar
        DBmask = self.mgf(seed, k - self.hlen - 1) # gerar mascara
        maskedDB = self.bitwiseXor(db, DBmask)
        seedMask = self.mgf(maskedDB, self.hlen)
        maskedSeed = self.bitwiseXor(seed, seedMask)
        return b'\x00' + maskedSeed + maskedDB # retorna o bytearray

    # Encripta uma mensagem com RSA - OAEP
    def encryptRsaOaep(self, message, publicKey):
        k = ceil((publicKey[1]).bit_length() / 8)

        assert len(message) <= k - self.hlen - 2

        e, n = publicKey
        c = self.oaepEncode(message, k)
        c = pow(self.os2ip(c), e, n)

        return self.i2osp(c, k)

    # Aplicacao do algoritmo OAEP
    # https://stringfixer.com/pt/RSA-OAEP
    def oaepDecode(self, cipher, k, label=b''):
        lhash = self.sha3(label) # hash da label
        maskedSeed, maskedDB = cipher[1:1 + self.hlen], cipher[1 + self.hlen:] # pega os bytes do seed e do DB
        seedMask = self.mgf(maskedDB, self.hlen) # gera a mascara do seed
        seed = self.bitwiseXor(maskedSeed, seedMask) # aplica a mascara no seed xor bit a bit
        DBmask = self.mgf(seed, k - self.hlen - 1) # gera a mascara do DB
        db = self.bitwiseXor(maskedDB, DBmask) # aplica a mascara no DB xor bit a bit
        _lhash = db[:self.hlen] # pega o hash da label
        assert lhash == _lhash
        i = self.hlen # tamanho do hash

        while i < len(db):
            if db[i] == 0:
                i += 1
                continue
            elif db[i] == 1:
                i += 1
                break
            else:
                raise Exception()
        m = db[i:]
        return m

    # Decripta uma mensagem com RSA - OAEP padding
    def decryptRsaOaep(self, cipher, privateKey):
        k = ceil((privateKey[1]).bit_length() / 8) # trunca o tamanho da chave
        assert len(cipher) == k
        assert k >= 2 * self.hlen + 2

        d, n = privateKey
        m = pow(self.os2ip(cipher), d, n)
        m = self.i2osp(m, k)

        return self.oaepDecode(m, k)

    # Decripta uma mensagem com RSA - OAEP
    def decryptMessage(self, signature, encryptedMessage, publicKey, privateKey):
        d, n = publicKey
        decrypted_message = self.decryptRsaOaep(encryptedMessage, privateKey)

        s = self.i2osp(pow(self.os2ip(signature), d, n),64)

        if(s == self.sha3(decrypted_message)):
            return decrypted_message.decode("utf-8")
        else:
            return "Erro na decriptacao"
