def input_file(file):
    f = open(file, 'r')
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
    print('======== Cifrador ========')
    print('Texto carregado de input_pt.txt')
    plaintext = input_file('input_pt.txt') # input("Digite a mensagem a ser cifrada: ") 
    key = input("Agora digite a chave para cifrá-la: ").upper()
    print(cipher(plaintext, key))

    print('\n======== Decifrador ========')
    ciphertext = cipher(plaintext, key)
    key = input("Digite a chave: ").upper()
    print(decipher(ciphertext, key))

    #ciphertext = "TV JMS YFG KZFHVI UCQ NYJ GVSG YJOXJ RINS CE HBRY JRWH JMS ZX NYJ XRNBNZJGN YVCEL OEISL F VFSBYK CH YVCJ DFRSSN XC JFM KMS JJFJVSHCEJ-GVBG KT U ROH XVY QWPVX KLNSNCD MZSUM FH TTBWVWHM IFCMJG FZH RY ZZAS VASLP RUP OHU FYKZFHJ ON XSPVS MYFFJ KCL IWHEJF JJZXFR AFJG FZH RY IKMSL YWGVX YOHSJK KBVS MYJ MZSUM MOM TBFP CHV AUCJ PZXWNFW VLY U LCIU RYRQ IW VCD VY NG UFFE MOHUXCGV OHU RUJMWHX BYMJF TFZFJ ZYJX NYFB FSQY F XRD UEI IWYSH YKCTJ BV WM F GI UIUKFYP BIIYCH TT KMS ZSBYI HYDUZY XSY YVY FRPRSHUXJG FK U HOVDFB RX U HCHWNRUEY NYJM YFR UWWPVS BZR BFRS R RIQJB KNAYJ TLFR MVWDYEYWHV-AYNX UEI EEJK RQZ RGCOK VCD KBVS C MOX QWMKJBYU HI FZF YVYP VUU HI YSFC W SJUUE HI BOFB IJ FBX ICQE BYRW VINCHP ZIULS FSQY RCLV OHU HI YVCEP IMJF DD JCFB FK WRRDUZLB YVCJ UIUKFYP BIIYCH BOM JJCUJBNCD UE WGGTFNRSH WFQNFW CE HBV AUKYSL MS NFG R ZUNDSL YVUK GILSRYU CGZSCOJ KBRY QRX NYJ LVQONZTB SJHQVJB KMSG FBX BVUK HBV CVAJQN TT YNG IJDYRYSX AWMZYG? BOM XVY MWM HZCVSH YNG WWWYEI II VCJ ACJYFYJX? ZK NYJ ZFWAYI GBV VUU DLFGOVCD NIFBMWJFLVI NYJ JYTHIXWOJY HI MWM PSYGNBA NT KMS CFHNVW CK KUJ ZYJX FZPSFP CH YVY NGMLJ IW HBZX KLJGNZTB UJDYEISX BVYKMSL N MYTIFU QIEYWHLJ GP KIIP UK PLZTBS QCXXJ II HOIS GP ONKJBNZTB KT NYJ AVSHFVROHJ QBRRPYIX CE HBV HYDUZY NH NFG R RYCNQUKJ JFNBN FBX NH NNRYEJR KMS WNSFU CZ RM ZSEOZWM Z TYRW NYFH Z PIIJ SFZ QZYV KMSMV RYKFWFJ POK W YFJY YC CJH PTI JJS DD FZYHFV RCWKWWLQHCVX CW MIL OLV HI ZBXVWGNRSR KMS JNHORYWIE"

    atk = Attack(lang='pt')
    atk.run(ciphertext)

if __name__ == "__main__":
    main()