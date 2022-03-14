# import matplotlib.pyplot as plt
# import numpy as np

def input_file(file):
    f = open(file, 'r', encoding='utf8')
    return f.read().upper()

def valid_char(char):
    return ord(char) >= ord('A') and ord(char) <= ord('Z')

def cipher(plaintext, key):
    clean_plaintext_arr = []
    for i in range(len(plaintext)):
        if valid_char(plaintext[i]):
            clean_plaintext_arr.append(plaintext[i])

    clean_plaintext = "".join(clean_plaintext_arr)

    # Corrige key, se necessario
    # cria a chave do tamanho do texto sem caracteres especiais e números
    builderKey = mendKey(key, len(clean_plaintext))

    ciphertext = []
    key_it = 0
    for i in range(len(plaintext)):
        # ord() retorna a posicao na tabela ascii 
        # para cada posicao da string somamos o codigo ascii e fazemos % 26 
        # e somamos 65 = ord('A')
        # assim garantimos que o texto cifrado sempre vai estar dentro do alfabeto
        if valid_char(plaintext[i]):
            builder = (ord(plaintext[i]) + ord(builderKey[key_it])) % 26
            builder += ord('A')
            ciphertext.append(chr(builder))
            key_it += 1
        else:
            ciphertext.append(plaintext[i])

    return("".join(ciphertext))

def decipher(ciphertext, key):
    clean_cipher_arr = []
    for i in range(len(ciphertext)):
        if valid_char(ciphertext[i]):
            clean_cipher_arr.append(ciphertext[i])

    clean_ciphertext = "".join(clean_cipher_arr)

    builderKey = mendKey(key, len(clean_ciphertext))

    plaintext = []
    key_it = 0
    for i in range(len(ciphertext)):
        # O processo eh identico ao cifrador, apenas sendo necessario subtrair
        if valid_char(ciphertext[i]):
            builder = (ord(ciphertext[i]) - ord(builderKey[key_it])) % 26
            builder += ord('A')
            plaintext.append(chr(builder))
            key_it += 1
        else:
            plaintext.append(ciphertext[i])
    
    return ("".join(plaintext))

# Faz key ter o tamanho do plaintext
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
    
class Attack():
    def __init__(self, lang='en', word_size=3):
        self.lang = lang
        self.word_size = word_size
        self.alphabet = self.letter_freq_alphabet()

    # carrega do arquivo txt a frequencia de cada letra no alfabeto escolhido
    def letter_freq_alphabet(self):
        alphabet = {}
        name = 'resources/frequencyEN.txt' if self.lang == 'en' else 'resources/frequencyPT.txt'
        with open(name, 'r') as file:
            for line in file:
                letter, freq = line[:-1].split(" ")
                alphabet[ letter.upper() ] = float(freq) / 100

        return alphabet

    # Encontra todas as sequencias de [WORD_SIZE] (X) letras que aparecem mais de uma vez na cifra
    def repeated_sequences(self, ciphertext):
        sequences = {}

        # Coleta todas as sequencias possíveis de X caracteres válidos (letras)
        for left in range(len(ciphertext)):
            curr_sequence = ciphertext[left:left+self.word_size]

            valid_sequence = True
            for curr_seq_char in curr_sequence:
                if not valid_char(curr_seq_char):
                    valid_sequence = False
                    break

            if valid_sequence:
                if curr_sequence in sequences:
                    sequences[curr_sequence] += 1
                else:
                    sequences[curr_sequence] = 1
        
        # Verifica e retorna as sequências que se repetem pelo menos uma vez na cifra
        repeats = {}
        for key, value in sequences.items():
            if value > 1:
                repeats[key] = value

        return repeats

    # Calcula as distancias entre todas as sequências que se repetem
    def calc_distances(self, ciphertext):
        sequences = self.repeated_sequences(ciphertext)

        distances = {}
        for i in range(2, 21):
            distances[i] = 0
        
        spacing = []
        for seq, qtd in sequences.items():

            # encontra a primeira ocorrencia da sequencia na cifra
            last_index = -1
            for i in range(len(ciphertext)):
                if seq == ciphertext[i:i+self.word_size]:
                    last_index = i + self.word_size
                    break
            
            # calcula as  distancias entre todas as ocorrencias da mesma sequencia 
            for i in range(qtd - 1):
                prox_index = last_index
                for j in range(last_index, len(ciphertext)):
                    if seq == ciphertext[j:j+self.word_size]:
                        if prox_index == last_index:
                            prox_index = j + self.word_size
                        spacing.append( (seq, j + self.word_size - last_index) )

                last_index = prox_index

        return spacing

    # Calcula quais os possiveis tamanhos para a chave
    def get_keysizes(self, ciphertext):
        distances = self.calc_distances(ciphertext)

        keysizes = {}

        for i in range(2, 21):
            keysizes[i] = 0

        # Verifica quais fatores são mais frequentes entre as distancias
        for word, distance in distances:
            for i in range(2, 21):
                if distance % i == 0:
                    keysizes[i] += 1

        # Os fatores com maior frequencia são os candidatos a tamanho de chave
        # Retorna os resultados ordenados, com os candidatos mais prováveis aparecendo primeiro
        return sorted(keysizes.items(), key=lambda k: (k[1], k[0]), reverse=True)

    def run(self, ciphertext):
        clean_cipher = []
        for i in range(len(ciphertext)):
            if valid_char(ciphertext[i]):
                clean_cipher.append(ciphertext[i])

        ciphertext = "".join(clean_cipher)

        keysizes = self.get_keysizes(ciphertext)
        print("(tamanho de chave, qtd ocorrencias): ", keysizes)
        for ks in range(3):
            # usar keysize para encontrar chave
            key_length, _ = keysizes[ks]
            print("Tamanho de chave: ", key_length)

            divided = []
            for i in range(key_length):
                divided.append('')

            for i in range(len(ciphertext)):
                divided[ i % key_length ] += ciphertext[i]

            freq_by_column = []
            for col in divided:
                # verifica frequencia de letras nessa coluna
                freq_abs = {}
                for i in range(26):
                    freq_abs[ chr(i + ord('A')) ] = 0

                for char in col:
                    if valid_char(char) and char in freq_abs:
                        freq_abs[char] += 1

                # transforma em porcentagem
                freq = {}
                for k, v in freq_abs.items():
                    freq[k] = v / len(col)

                freq_by_column.append(freq)

            ####################################################################################################
            # pegando o maior
            ####################################################################################################

            #greatest in the alphabet
            ga = max(self.alphabet, key=self.alphabet.get)
            for i in range(key_length):
                col = freq_by_column[i]
                ordered = sorted(col.items(), key=lambda k: k[1], reverse=True)

                for j in range(4):
                    k, _ = ordered[j]
                    if ord(k) >= ord(ga):
                        print( chr(ord(k) - ord(ga) + ord('A')) , end=' ')
                    else:
                        print( chr( ord('Z') - abs(ord(k) - ord(ga) + 1 ) ) , end=' ' )

                print('')

            ####################################################################################################
            # grafico
            ####################################################################################################

            # labels = list(self.alphabet.keys())
            # values = list(self.alphabet.values())

            # fig, ax = plt.subplots()
            # x = np.arange(len(labels))
            # width = 0.2

            # ag = ax.bar( x - width/2 , values, width=width, label='English')
            # c0 = ax.bar( x + width/2 , list(freq_by_column[0].values()), width=width, label='Coluna 0' )

            # ax.set_ylabel('Porcentagem de ocorrência')
            # ax.set_xticks( x, labels )
            # ax.legend()

            # fig.tight_layout()

            # plt.show()


def main():
    print("======== Cifra de Vigenere ========")
    mode = 1
    while mode:
        mode = int(input("\nEscolha um modo: \n1. Ataque desafio 1\n2. Ataque desafio 2\n3. Cifrador\n4. Decifrador\n0. Sair\n"))
        if mode == 1:
            ciphertext = input_file("desafio1.txt")

            atk = Attack('en')
            atk.run(ciphertext)

            key = input("Digite a chave: ").upper()
            print(decipher(ciphertext, key))
        elif mode == 2:
            ciphertext = input_file('desafio2.txt')

            atk = Attack('pt')
            atk.run(ciphertext)

            key = input("Digite a chave: ").upper()
            print(decipher(ciphertext, key))
        elif mode == 3:
            print('======== Cifrador ========')
            plaintext = input("Digite a mensagem a ser cifrada: ").upper()
            key = input("Agora digite a chave para cifrá-la: ").upper()
            print(cipher(plaintext, key))
        elif mode == 4:
            print('\n======== Decifrador ========')
            ciphertext = input("Digite a mensagem a ser decifrada: ").upper()
            key = input("Digite a chave: ").upper()
            print(decipher(ciphertext, key))
                

if __name__ == "__main__":
    main()