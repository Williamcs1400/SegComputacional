def input_file(file):
    f = open(file, 'r', encoding='utf8')
    return f.read().upper()

def valid_char(char):
    return ord(char) >= ord('A') and ord(char) <= ord('Z')

def cipher(plaintext, key):
    # Corrige key, se necessario
    builderKey = mendKey(key, len(plaintext))

    ciphertext = []
    for i in range(len(plaintext)):
        # ord() retorna a posicao na tabela ascii 
        # para cada posicao da string somamos o codigo ascii e fazemos % 26 
        # e somamos 65 = ord('A')
        # assim garantimos que o texto cifrado sempre vai estar dentro do alfabeto
        if valid_char(plaintext[i]):
            builder = (ord(plaintext[i]) + ord(builderKey[i])) % 26
            builder += ord('A')
            ciphertext.append(chr(builder))
        else:
            ciphertext.append(plaintext[i])
    return("".join(ciphertext))

def decipher(ciphertext, key):
    builderKey = mendKey(key, len(ciphertext))

    plaintext = []
    for i in range(len(ciphertext)):
        # O processo eh identico ao cifrador, apenas sendo necessario subtrair
        if valid_char(ciphertext[i]):
            builder = (ord(ciphertext[i]) - ord(builderKey[i])) % 26
            builder += ord('A')
            plaintext.append(chr(builder))
        else:
            plaintext.append(ciphertext[i])
    
    return ("".join(plaintext))

# Faz key ter o tamanho do plaintext
def mendKey(key, size):
    if(len(key) == size):
        return key

    keyBuilder = ''
    for i in range(size):
        keyBuilder += key[ i % len(key) ]

    return keyBuilder

class Attack:
    def __init__(self, lang='en'):
        self.lang = lang
        self.alphabet = self.letter_freq_alphabet()
    
    def letter_freq_alphabet(self):
        alphabet = {}
        name = 'frequencyEN.txt' if self.lang == 'en' else 'frequencyPT.txt'
        with open(name, 'r') as file:
            for line in file:
                letter, freq = line[:-1].split(" ")
                alphabet[ letter.upper() ] = float(freq) / 100

        return alphabet

    def expected_ic(self):
        expected_ic = 0
        for i in range(26):
            expected_ic += self.alphabet[ chr(i + ord('A')) ] ** 2
        expected_ic /= (1/26)
        
        return expected_ic

    def run(self, ciphertext):
        #ciphertext = "".join(ciphertext.split(" "))
        candidate_lengths = {}
        avgs = {}

        for key_length in range(1,20):
            
            divided = []
            for i in range(key_length):
                divided.append('')
            
            for i in range(len(ciphertext)):
                divided[ i % key_length ] += ciphertext[i]

            candidate_lengths[key_length] = []
            for str_i in range(key_length):
                partial_cipher = divided[str_i]
                # calculate letter frequency
                letter_freq_cipher = []
                for i in range(26):
                    letter_freq_cipher.append(0)

                n = 0
                for i in range(len(partial_cipher)):
                    if valid_char(partial_cipher[i]):
                        letter_freq_cipher[ ord(partial_cipher[i]) - ord('A') ] += 1
                        n += 1


                # calculate index of coincidence
                ic = 0
                for i in range(26):
                    ic += letter_freq_cipher[i] * (letter_freq_cipher[i] - 1)
                ic /= n * (n - 1) / 26
                #print(ic)
                candidate_lengths[key_length].append(ic)
            
            avg = 0
            for i in candidate_lengths[key_length]:
                avg += i
            
            avg /= key_length

            avgs[key_length] = avg

        avgs_arr = sorted(avgs.items(), key=lambda k: k[1], reverse=True)
        print(avgs_arr)
        #candidate_key = avgs_arr[0]
        #print(candidate_key)

def main():
    # print('======== Cifrador ========')
    # print('Texto carregado de input_pt.txt')
    # plaintext = input_file('input_pt.txt') # input("Digite a mensagem a ser cifrada: ") 
    # key = input("Agora digite a chave para cifrá-la: ").upper()
    # print(cipher(plaintext, key))

    # print('\n======== Decifrador ========')
    # ciphertext = cipher(plaintext, key)
    # key = input("Digite a chave: ").upper()
    # print(decipher(ciphertext, key))

    ciphertext = input_file('desafio1.txt')

    atk = Attack(lang='pt')
    atk.run(ciphertext)

if __name__ == "__main__":
    main()