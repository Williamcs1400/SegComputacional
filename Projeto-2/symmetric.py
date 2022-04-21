from logging import exception
import os
import numpy as np
from const import s_box, g_mul2, g_mul3, r_con
from pprint import pprint

class SymKey:
  @staticmethod
  def generate(bits: int = 256):
    return os.urandom(bits // 8)

class AES_Util:
  # conta a quantidade de rounds a partir do tamanho da chave (em bits)
  @staticmethod
  def count_rounds(key_length):
    if key_length == 128:
      return 10
    elif key_length == 192:
      return 12
    elif key_length == 256:
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
  # output eh uma string
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

class AES:
  def __init__(self, key):
    if type(key) is str:
      key = key.encode()
    
    self.key = key
    self.rounds = AES_Util.count_rounds(len(key) * 8)
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

      w = bytes(i^j for i,j in zip(w, key_cols[-it_size]))
      key_cols.append(w)

    res = [key_cols[4*i : 4*(i+1)] for i in range(len(key_cols) // 4)]
    for i in range(len(res)):
      for j in range(len(res[i])):
        if type(res[i][j]) is bytes:
          res[i][j] = [b for b in res[i][j]]

      res[i] = np.transpose(res[i]).tolist()

    return res

  # Cipher algorithm, FIPS197 5.1
  def cipher(self, message: str):
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


  def encrypt(self, message: str):
    return ""

  def decrypt(self, ciphertext: str):
    return ""

  