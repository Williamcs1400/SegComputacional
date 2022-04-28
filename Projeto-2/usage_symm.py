from symmetric import AES, SymKey

#key = "aesEncryptionKey"
msg = "HELLO DARKNESS MY OLD FRIEND, I'VE COME TO TALK WITH YOU AGAIN"
print("Plaintext: ", msg.encode().hex())

key = SymKey.generate(256)
aes = AES(key)

print("Generated key: ", key.hex())

cipher = aes.encrypt(msg)
print("Ciphertext: ", cipher.hex())

plain = aes.decrypt(cipher)
print("Decoded plaintext: ", plain)