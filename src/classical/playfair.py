import string


def build_matrix(keyword: str) -> list:
    keyword = keyword.upper().replace('J', 'I')
    
    used = set()
    matrix_chars = []
    
    for char in keyword:
        if char.isalpha() and char not in used and char != 'J':
            matrix_chars.append(char)
            used.add(char)
    
    for char in string.ascii_uppercase:
        if char not in used and char != 'J':
            matrix_chars.append(char)
            used.add(char)
    
    matrix = []
    for i in range(5):
        matrix.append(matrix_chars[i*5:(i+1)*5])
    
    return matrix


def find_position(matrix: list, char: str):
    char = char.upper().replace('J', 'I')
    for i in range(5):
        for j in range(5):
            if matrix[i][j] == char:
                return (i, j)
    return None


def prepare_message(message: str) -> str:
    message = message.upper().replace('J', 'I')
    message = ''.join(c for c in message if c.isalpha())
    
    prepared = []
    i = 0
    while i < len(message):
        if i == len(message) - 1:
            prepared.append(message[i])
            prepared.append('X')
            i += 1
        elif message[i] == message[i+1]:
            prepared.append(message[i])
            prepared.append('X')
            i += 1
        else:
            prepared.append(message[i])
            prepared.append(message[i+1])
            i += 2
    
    if len(prepared) % 2 != 0:
        prepared.append('X')
    
    return ''.join(prepared)


def encrypt(message: str, keyword: str) -> str:
    matrix = build_matrix(keyword)
    prepared = prepare_message(message)
    
    result = []
    
    for i in range(0, len(prepared), 2):
        char1 = prepared[i]
        char2 = prepared[i+1]
        
        row1, col1 = find_position(matrix, char1)
        row2, col2 = find_position(matrix, char2)
        
        if row1 == row2:
            enc_char1 = matrix[row1][(col1 + 1) % 5]
            enc_char2 = matrix[row2][(col2 + 1) % 5]
        
        elif col1 == col2:
            enc_char1 = matrix[(row1 + 1) % 5][col1]
            enc_char2 = matrix[(row2 + 1) % 5][col2]
        
        else:
            enc_char1 = matrix[row1][col2]
            enc_char2 = matrix[row2][col1]
        
        result.append(enc_char1)
        result.append(enc_char2)
    
    return ''.join(result)


def decrypt(encrypted_message: str, keyword: str) -> str:
    matrix = build_matrix(keyword)
    encrypted_message = encrypted_message.upper().replace('J', 'I')
    
    result = []
    
    for i in range(0, len(encrypted_message), 2):
        char1 = encrypted_message[i]
        char2 = encrypted_message[i+1]
        
        row1, col1 = find_position(matrix, char1)
        row2, col2 = find_position(matrix, char2)
        
        if row1 == row2:
            dec_char1 = matrix[row1][(col1 - 1) % 5]
            dec_char2 = matrix[row2][(col2 - 1) % 5]
        
        elif col1 == col2:
            dec_char1 = matrix[(row1 - 1) % 5][col1]
            dec_char2 = matrix[(row2 - 1) % 5][col2]
        
        else:
            dec_char1 = matrix[row1][col2]
            dec_char2 = matrix[row2][col1]
        
        result.append(dec_char1)
        result.append(dec_char2)
    
    return ''.join(result)


def display_matrix(matrix: list):
    print("\n    0 1 2 3 4")
    for i, row in enumerate(matrix):
        print(f"{i}:  {' '.join(row)}")
    print()