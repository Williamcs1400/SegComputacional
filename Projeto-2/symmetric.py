import os
import numpy as np
from const import s_box, inv_s_box, r_con, g_mul2, g_mul3, g_mul9, g_mul11, g_mul13, g_mul14, aes_key_sizes

class SymKey:
  @staticmethod
  def generate(bits = 128):
    return os.urandom(bits // 8)

class AES_Util:
  # Conta a quantidade de rounds a partir do tamanho da chave (em bytes)
  @staticmethod
  def count_rounds(key_length: int):
    if key_length == 16:
      return 10
    elif key_length == 24:
      return 12
    elif key_length == 32:
      return 14

  # transforma o array de input num array de estado (state)
  # state eh um array de colunas (4x4), vide FIPS197 3.5
  @staticmethod
  def bytes_to_matrix(message):
    matrix = [[] for i in range(4)]
    for i in range(len(message)):
      matrix[i % 4].append(message[i])

    return matrix

  # transforma o array de estado (state) num array de output
  @staticmethod
  def matrix_to_bytes(matrix):
    bytearr = []
    for i in range(4):
      for j in range(4):
        bytearr.append(matrix[j][i])

    return bytes(bytearr)

  # Transformacao SubBytes FIPS197 5.1.1
  @staticmethod
  def sub_bytes(state):
    for i in range(4):
      for j in range(4):
        state[i][j] = s_box[state[i][j]]

  # Transformacao ShiftRows FIPS197 5.1.2
  @staticmethod
  def shift_rows(state):
    for i in range(1,4):
      state[i] = list(np.roll(state[i], -i))

  # Transformacao MixColumns FIPS197 5.1.3
  @staticmethod
  def mix_columns(state):
    for i in range(4):
      a0, a1, a2, a3 = state[0][i], state[1][i], state[2][i], state[3][i]
      state[0][i] = g_mul2[a0] ^ g_mul3[a1] ^ a2 ^ a3
      state[1][i] = a0 ^ g_mul2[a1] ^ g_mul3[a2] ^ a3
      state[2][i] = a0 ^ a1 ^ g_mul2[a2] ^ g_mul3[a3]
      state[3][i] = g_mul3[a0] ^ a1 ^ a2 ^ g_mul2[a3]

  # Transformacao AddRoundKey FIPS197 5.1.4
  @staticmethod
  def add_round_key(state, key):
    for i in range(4):
      for j in range(4):
       state[i][j] ^= key[i][j]

  # Transformacao InvShiftRows FIPS197 5.3.1
  @staticmethod
  def inv_shift_rows(state):
    for i in range(1,4):
      state[i] = list(np.roll(state[i], i))

  # Transformacao InvSubBytes FIPS197 5.3.2
  @staticmethod
  def inv_sub_bytes(state):
    for i in range(4):
      for j in range(4):
        state[i][j] = inv_s_box[state[i][j]]

  # Transformacao InvMixColumns FIPS197 5.3.3
  @staticmethod
  def inv_mix_columns(state):
    for i in range(4):
      a0, a1, a2, a3 = state[0][i], state[1][i], state[2][i], state[3][i]
      state[0][i] = g_mul14[a0] ^ g_mul11[a1] ^ g_mul13[a2] ^ g_mul9[a3]
      state[1][i] = g_mul9[a0] ^ g_mul14[a1] ^ g_mul11[a2] ^ g_mul13[a3]
      state[2][i] = g_mul13[a0] ^ g_mul9[a1] ^ g_mul14[a2] ^ g_mul11[a3]
      state[3][i] = g_mul11[a0] ^ g_mul13[a1] ^ g_mul9[a2] ^ g_mul14[a3]

  @staticmethod
  def zip_xor(a, b):
    return bytes(i^j for i,j in zip(a, b))

  @staticmethod
  def generate_counter():
    return int.to_bytes(1, 16, 'big')

  @staticmethod
  def increment_byte(original: bytes):
    num = int.from_bytes(original, 'big') + 1
    return num.to_bytes(16, 'big')

class AES:
  def __init__(self, key):
    if type(key) is str:
      key = key.encode()

    key_size = len(key)
    if key_size not in aes_key_sizes:
      raise Exception("Key size of {} bytes not in AES standard".format(key_size))
    
    self.key = key
    self.rounds = AES_Util.count_rounds(key_size)
    self.exp_keys = self.__expanded_keys()

  # Expansao de chave FIPS197 5.2
  def __expanded_keys(self):
    key_cols = AES_Util.bytes_to_matrix(self.key)
    key_cols = np.transpose(key_cols).tolist()
    it_size = len(self.key) // 4

    i = 1
    while len(key_cols) < (self.rounds + 1) * 4:
      w = list(key_cols[-1])
      if len(key_cols) % it_size == 0:
        w.append(w.pop(0))
        w = [s_box[b] for b in w]
        w[0] ^= r_con[i]
        i += 1
      elif len(self.key) == 32 and len(key_cols) % it_size == 4:
        w = [s_box[b] for b in w]

      w = AES_Util.zip_xor(w, key_cols[-it_size])
      key_cols.append(w)

    res = [key_cols[4*i : 4*(i+1)] for i in range(len(key_cols) // 4)]
    for i in range(len(res)):
      for j in range(len(res[i])):
        if type(res[i][j]) is bytes:
          res[i][j] = [b for b in res[i][j]]

      res[i] = np.transpose(res[i]).tolist()

    return res

  # Algoritmo de cifra (Cipher), FIPS197 5.1
  def cipher(self, message):
    if len(message) != 16:
      raise Exception("Bloco precisa de 16 digitos")

    if type(message) is str:
      message = message.encode()

    state = AES_Util.bytes_to_matrix(message)

    AES_Util.add_round_key(state, self.exp_keys[0])

    for i in range(1, self.rounds):
      AES_Util.sub_bytes(state)
      AES_Util.shift_rows(state)
      AES_Util.mix_columns(state)
      AES_Util.add_round_key(state, self.exp_keys[i])

    AES_Util.sub_bytes(state)
    AES_Util.shift_rows(state)
    AES_Util.add_round_key(state, self.exp_keys[-1])

    return AES_Util.matrix_to_bytes(state)

  # Realiza encriptacao no modo CTR
  def encrypt(self, message, iv: bytes = None) -> bytes:
    if type(message) is str:
      message = message.encode()

    message_blocks = [message[i:i+16] for i in range(0, len(message), 16)]

    # gera counter (iniciado em 1 por padrao)
    # se initialization vector nao for fornecido
    if iv:
      counter = iv
    else:
      counter = AES_Util.generate_counter()

    encrypted = []
    for block in message_blocks:
      encrypted.append(AES_Util.zip_xor(block, self.cipher(counter)))
      counter = AES_Util.increment_byte(counter)

    return b''.join(encrypted)

  # Realiza desencriptacao no modo CTR
  def decrypt(self, ciphertext, iv: bytes = None) -> bytes:
    if type(ciphertext) is str:
      ciphertext = ciphertext.encode()

    ciphertext_blocks = [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]

    # gera counter (iniciado em 1 por padrao)
    # se initialization vector nao for fornecido
    if iv:
      counter = iv
    else:
      counter = AES_Util.generate_counter()

    decrypted = []
    for block in ciphertext_blocks:
      decrypted.append(AES_Util.zip_xor(block, self.cipher(counter)))
      counter = AES_Util.increment_byte(counter)

    return b''.join(decrypted)