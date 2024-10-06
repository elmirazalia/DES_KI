# fungsi padding
def pad(text):
    padding_len = 8 - (len(text) % 8)
    padding = chr(padding_len) * padding_len
    return text + padding

# fungsi unpad
def unpad(text):
    padding_len = ord(text[-1])
    return text[:-padding_len]

# key generator
def keyGenerator(key):
    global list_of_key
    list_of_key = []
    
    key_binary = ''.join(f'{ord(i):08b}' for i in key)
    
    key_56bit = key_binary[:56]
    
    for i in range(16):
        rotated_key = key_56bit[i:] + key_56bit[:i]
        list_of_key.append(rotated_key[:48])

# konversi biner-heksadesimal
def to_hex(binary_str):
    return ''.join(f'{int(binary_str[i:i+4], 2):X}' for i in range(0, len(binary_str), 4))

# fungsi initial permutation-final permutation
def initialPermutation(binary):
    initial_permutation = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
    return ''.join(binary[initial_permutation[i] - 1] for i in range(64))

def finalPermutation(binary):
    final_permutation = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
    return ''.join(binary[final_permutation[i] - 1] for i in range(64))

# fungsi substitution box
def sBox(binary):
    sbox = [
        [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7], [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8], [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0], [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
        [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10], [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5], [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15], [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
        [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8], [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1], [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7], [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
        [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15], [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9], [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4], [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
        [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9], [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6], [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14], [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
        [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11], [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8], [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6], [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
        [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1], [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6], [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2], [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
        [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7], [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2], [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8], [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
    ]
    
    result = ''
    for i in range(0, len(binary), 6):
        row = int(binary[i] + binary[i+5], 2)
        col = int(binary[i+1:i+5], 2)
        temp = bin(sbox[i // 6][row][col])[2:]
        result += temp.zfill(4)
    
    return result

# fungsi feistel
def feistel(binary, rounds):
    expansion_table = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
    straight_permutation_table = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
    
    expanded = ''.join(binary[expansion_table[i] - 1] for i in range(48))
    xor_result = ''.join(str(int(expanded[i]) ^ int(list_of_key[rounds][i])) for i in range(48))
    
    sbox_result = sBox(xor_result)
    result = ''.join(sbox_result[straight_permutation_table[i] - 1] for i in range(32))
    
    return result

# fungsi enkripsi
def DES(text):  
    binary = ''.join(f'{ord(i):08b}' for i in text)
    binary = initialPermutation(binary)
    
    left = binary[:32]
    right = binary[32:]
    
    for i in range(16):
        temp_right = right
        right = feistel(right, i)
        right = ''.join(str(int(left[j]) ^ int(right[j])) for j in range(32))
        left = temp_right
    
    final = right + left
    result = finalPermutation(final)
    return result

# fungsi dekripsi
def DES_decrypt(binary):  
    binary = initialPermutation(binary)
    
    left = binary[:32]
    right = binary[32:]
    
    for i in range(15, -1, -1):
        temp_right = right
        right = feistel(right, i)
        right = ''.join(str(int(left[j]) ^ int(right[j])) for j in range(32))
        left = temp_right
    
    final = right + left
    result = finalPermutation(final)
    return result

# konversi biner-teks
def binary_to_text(binary_str):
    text = ''
    for i in range(0, len(binary_str), 8):  
        byte = binary_str[i:i+8]
        text += chr(int(byte, 2)) 
    return text

plaintext = input("Input plaintext: ")
key = input("Input key: ")

keyGenerator(key)

plaintext = pad(plaintext)

# encrypt
ciphertext = ''
for i in range(0, len(plaintext), 8):
    block = plaintext[i:i+8]
    binary_ciphertext = DES(block)
    ciphertext += binary_ciphertext 

print("Ciphertext: " + ciphertext)
print("Ciphertext hex encoded: " + to_hex(ciphertext))

# decrypt
decrypted_binary = ''
for i in range(0, len(ciphertext), 64):  
    block = ciphertext[i:i+64]
    binary_decrypted = DES_decrypt(block)
    decrypted_binary += binary_decrypted

# konversi biner-teks 
decrypted_text = binary_to_text(decrypted_binary)

# unpad decrypt teks
decrypted_text = unpad(decrypted_text)

print("Decrypted text: " + decrypted_text)
