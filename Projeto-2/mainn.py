from symmetric import AES, AES_Util, SymKey

#aes = AES(SymKey.generate(128))
#print("key:", aes.key.hex())

key = "aesEncryptionKey"
msg = "1234567890123456"

aes = AES(key)
print(aes.cipher(msg).hex())

# print(AES_Util.bytes_to_matrix(msg))

# print(AES_Util.matrix_to_bytes( AES_Util.bytes_to_matrix(msg) ))

#state = [[0x8e,0x9f,0xf1,0xc6],[0x4d,0xdc,0xe1,0xc7],[0xa1,0x58,0xd1,0xc8],[0xbc,0x9d,0xc1,0xc9]]
#AES_Util.sub_bytes(state)

# state = [[0x8e,0x9f,0x01,0xc6],[0x4d,0xdc,0x01,0xc6],[0xa1,0x58,0x01,0xc6],[0xbc,0x9d,0x01,0xc6]]
# AES_Util.shift_rows(state)

#state = [[0xdb,0xf2,0x01,0xc6],[0x13,0x0a,0x01,0xc6],[0x53,0x22,0x01,0xc6],[0x45,0x5c,0x01,0xc6]]
#line = [0xdb, 0x13, 0x53, 0x45]
#AES_Util.mix_columns(state)

#for i in state:
#  print([hex(x) for x in i])