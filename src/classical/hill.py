def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def matrix_determinant_2x2(matrix):
    return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26


def matrix_determinant_3x3(matrix):
    det = (matrix[0][0] * (matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1]) -
           matrix[0][1] * (matrix[1][0] * matrix[2][2] - matrix[1][2] * matrix[2][0]) +
           matrix[0][2] * (matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0]))
    return det % 26


def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return None


def matrix_inverse_2x2(matrix):
    det = matrix_determinant_2x2(matrix)
    det_inv = mod_inverse(det, 26)
    
    if det_inv is None:
        raise ValueError("La matrice n'est pas inversible modulo 26")
    
    inverse = [
        [(det_inv * matrix[1][1]) % 26, (det_inv * (-matrix[0][1])) % 26],
        [(det_inv * (-matrix[1][0])) % 26, (det_inv * matrix[0][0]) % 26]
    ]
    return inverse


def matrix_inverse_3x3(matrix):
    det = matrix_determinant_3x3(matrix)
    det_inv = mod_inverse(det, 26)
    
    if det_inv is None:
        raise ValueError("La matrice n'est pas inversible modulo 26")
    
    adj = [
        [(matrix[1][1] * matrix[2][2] - matrix[1][2] * matrix[2][1]) % 26,
         (matrix[0][2] * matrix[2][1] - matrix[0][1] * matrix[2][2]) % 26,
         (matrix[0][1] * matrix[1][2] - matrix[0][2] * matrix[1][1]) % 26],
        [(matrix[1][2] * matrix[2][0] - matrix[1][0] * matrix[2][2]) % 26,
         (matrix[0][0] * matrix[2][2] - matrix[0][2] * matrix[2][0]) % 26,
         (matrix[0][2] * matrix[1][0] - matrix[0][0] * matrix[1][2]) % 26],
        [(matrix[1][0] * matrix[2][1] - matrix[1][1] * matrix[2][0]) % 26,
         (matrix[0][1] * matrix[2][0] - matrix[0][0] * matrix[2][1]) % 26,
         (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % 26]
    ]
    
    inverse = [[(det_inv * adj[i][j]) % 26 for j in range(3)] for i in range(3)]
    return inverse


def matrix_multiply(matrix, vector):
    n = len(matrix)
    result = [0] * n
    for i in range(n):
        for j in range(n):
            result[i] = (result[i] + matrix[i][j] * vector[j]) % 26
    return result


def get_block_size(matrix):
    return len(matrix)


def is_matrix_invertible(matrix):
    n = len(matrix)
    try:
        if n == 2:
            det = matrix_determinant_2x2(matrix)
        elif n == 3:
            det = matrix_determinant_3x3(matrix)
        else:
            raise ValueError("Seules les matrices 2x2 et 3x3 sont supportées")
        
        return gcd(det, 26) == 1
    except:
        return False


def encrypt(message: str, key_matrix) -> str:
    n = get_block_size(key_matrix)
    
    if not is_matrix_invertible(key_matrix):
        raise ValueError("La matrice clé n'est pas inversible modulo 26")
    
    message_clean = ''.join(c.upper() for c in message if c.isalpha())
    
    if len(message_clean) % n != 0:
        message_clean += 'X' * (n - len(message_clean) % n)
    
    result = []
    
    for i in range(0, len(message_clean), n):
        block = message_clean[i:i+n]
        vector = [ord(c) - ord('A') for c in block]
        
        encrypted_vector = matrix_multiply(key_matrix, vector)
        
        for val in encrypted_vector:
            result.append(chr(val + ord('A')))
    
    return ''.join(result)


def decrypt(encrypted_message: str, key_matrix) -> str:
    n = get_block_size(key_matrix)
    
    if not is_matrix_invertible(key_matrix):
        raise ValueError("La matrice clé n'est pas inversible modulo 26")
    
    if n == 2:
        inverse_matrix = matrix_inverse_2x2(key_matrix)
    elif n == 3:
        inverse_matrix = matrix_inverse_3x3(key_matrix)
    else:
        raise ValueError("Seules les matrices 2x2 et 3x3 sont supportées")
    
    encrypted_clean = encrypted_message.upper()
    
    if len(encrypted_clean) % n != 0:
        raise ValueError("Le message chiffré n'a pas une longueur correcte")
    
    result = []
    
    for i in range(0, len(encrypted_clean), n):
        block = encrypted_clean[i:i+n]
        vector = [ord(c) - ord('A') for c in block]
        
        decrypted_vector = matrix_multiply(inverse_matrix, vector)
        
        for val in decrypted_vector:
            result.append(chr(val + ord('A')))
    
    return ''.join(result)