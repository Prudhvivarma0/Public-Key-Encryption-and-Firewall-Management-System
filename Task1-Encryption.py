import random
import math
import json

def is_prime(n):
    """
    Check if a number is a prime number.

    Args:
        n (int): The number to check.

    Returns:
        bool: True if the number is prime, False otherwise.
    """
    #Reference: https://www.geeksforgeeks.org/python-program-to-check-whether-a-number-is-prime-or-not/
    if n <= 1:
        return False                                                
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def find_prime_above(min_value):
    """
    Tries to find the next prime number >= min_value.

    Args:
        min_value (int): The minimum value to start searching for a prime number.

    Returns:
        int: The smallest prime number greater than or equal to min_value.
    """
    candidate = max(min_value, 2)                                    
    while not is_prime(candidate):
        candidate += 1
    return candidate

def generate_keys():
    """
    Generate and save public and private keys with length 2-64.
    List `e` is sums of previous elements plus random (1-100).
    Prime `q` > 2 * last `e`, `w` coprime with `q`.
    Public key: `(w * ei) % q` for each `ei` in `e`.
    Saves to 'public_key.txt' and 'private_key.txt'.
    """
    while True:
        n = input("Choose e(n) (between 2 and 64): ").strip()
        if n.isdigit() and 2 <= int(n) <= 64:
            n = int(n)
            break
        print("Invalid input. Please enter a number between 2 and 64.")

    e = []
    sum_prev = 0
    for _ in range(n):
        ei = sum_prev + random.randint(1, 100)   # limited random generation between 1-100 due to computational reasons 
        e.append(ei)
        sum_prev = sum(e)

    q = find_prime_above(e[-1] * 2)             # q prime number greater than twice the last element in the e list
    w = random.randint(2, q - 1)
    while math.gcd(w, q) != 1:                  # w number between 2 and q-1, where q and w are coprime 
        w = random.randint(2, q - 1)

    h = [(w * ei) % q for ei in e]              # computing the public key

    public_key = h
    private_key = (e, q, w)

    with open("public_key.txt", "w") as f:
        f.write('\n'.join(map(str, public_key)))  # Saving keys to files

    with open("private_key.txt", "w") as f:
        f.write(str(q) + '\n')
        f.write(str(w) + '\n')
        f.write('\n'.join(map(str, e)))

    print(f"Keys generated with length {n} and saved to files 'public_key.txt' and 'private_key.txt'.")

def load_public_key(file_name):
    with open(file_name, "r") as f:
        return [int(line.strip()) for line in f if line.strip()]

def load_private_key(file_name):
    with open(file_name, "r") as f:
        lines = f.read().splitlines()
    q = int(lines[0])
    w = int(lines[1])
    e = [int(x) for x in lines[2:]]
    return (e, q, w)

def chunk_message(message_bits, chunk_size):
    for i in range(0, len(message_bits), chunk_size):
        yield message_bits[i:i + chunk_size]                                    # Trying to yield chunks of the specified size from message bits.
                                                                        
       

def pad_chunk(chunk, chunk_size):
     return chunk + [0] * (chunk_size - len(chunk))                             # Trying to pad the chunk with zeros to match the chunk size
   

def encrypt_chunk(chunk, public_key):
    return sum(public_key[j] * chunk[j] for j in range(len(chunk)))             # Trying to encrypt the chunk using the public key

def encrypt(message_bits, public_key):
    chunk_size = len(public_key)                                                # Trying to set chunk size to the length of the public key
    ciphertext_chunks = []

    for chunk in chunk_message(message_bits, chunk_size):
        if len(chunk) < chunk_size:                                             # Trying to pad the chunk if it's smaller than the chunk size
            chunk = pad_chunk(chunk, chunk_size)
        ciphertext_chunks.append(encrypt_chunk(chunk, public_key))              # Trying to encrypt the chunk using the public key

    return ciphertext_chunks

def decrypt_chunk(c_prime, e):
    chunk_bits = []                        # Trying to convert the chunk back to bits
    for ei in reversed(e):
        if c_prime >= ei:
            chunk_bits.insert(0, 1) 
            c_prime -= ei
        else:
            chunk_bits.insert(0, 0)  
    return chunk_bits

def decrypt(ciphertext_chunks, private_key):
    e, q, w = private_key
    w_inv = pow(w, -1, q)  # Trying to find the modular inverse of w
    message_bits = []

    for c in ciphertext_chunks:
        c_prime = (c * w_inv) % q  # Trying to decrypt the chunk
        message_bits.extend(decrypt_chunk(c_prime, e))  # Trying to convert the decrypted chunk back to bits

    return message_bits


def text_to_bits(text):
    return [int(bit) for byte in bytearray(text, 'utf-8') for bit in format(byte, '08b')]
                                                                                                #converting text to bits and vice versa
def bits_to_text(bits):
    byte_chunks = [''.join(map(str, bits[i:i + 8])) for i in range(0, len(bits), 8)]
    bytes_array = bytearray([int(b, 2) for b in byte_chunks])
    return bytes(bytes_array).decode('utf-8', errors='ignore')

def main():
    action = input("Choose action (generate/encrypt/decrypt): ").strip().lower()

    if action == "generate":
        generate_keys()

    elif action == "encrypt":
        input_file = input("Enter the plaintext file name: ").strip()
        public_key_file = input("Enter the public key file name: ").strip()

        try:
            public_key = load_public_key(public_key_file)
        except FileNotFoundError:
            print(f"Error: Public key file '{public_key_file}' not found.")
            return
        except IOError as e:
            print(f"Error: Unable to read public key file '{public_key_file}'. Reason: {e}")
            return

        try:
            with open(input_file, 'r') as f:
                plaintext = f.read()                                                   # Reading plaintext and convert to binary
        except FileNotFoundError:
            print(f"Error: Plaintext file '{input_file}' not found.")
            return
        except IOError as e:
            print(f"Error: Unable to read plaintext file '{input_file}'. Reason: {e}")
            return

        message_bits = text_to_bits(plaintext)

        ciphertext_chunks = encrypt(message_bits, public_key)

        output_file = input("Enter the output file name for ciphertext: ").strip()
        try:
            with open(output_file, 'w') as f:                                           # Save ciphertext chunks to file
                json.dump(ciphertext_chunks, f)
            print(f"Encryption complete. Ciphertext saved to {output_file}")
        except IOError as e:
            print(f"Error: Unable to write ciphertext to file '{output_file}'. Reason: {e}")

    elif action == "decrypt":
        input_file = input("Enter the ciphertext file name: ").strip()
        private_key_file = input("Enter the private key file name: ").strip()

        try:
            private_key = load_private_key(private_key_file)
        except FileNotFoundError:
            print(f"Error: Private key file '{private_key_file}' not found.")
            return
        except IOError as e:
            print(f"Error: Unable to read private key file '{private_key_file}'.")
            return

        try:
            with open(input_file, 'r') as f:
                ciphertext_chunks = json.load(f)  # Read ciphertext chunks from file
        except FileNotFoundError:
            print(f"Error: Ciphertext file '{input_file}' not found.")
            return
        except IOError as e:
            print(f"Error: Unable to read ciphertext file '{input_file}'.")
            return

        decrypted_bits = decrypt(ciphertext_chunks, private_key)
        decrypted_text = bits_to_text(decrypted_bits)

        output_file = input("Enter the output file name for decrypted text: ").strip()
        try:
            with open(output_file, 'w') as f:  # Save decrypted text to file
                f.write(decrypted_text)
            print(f"Decryption complete. Decrypted text saved to {output_file}")
        except IOError as e:
            print(f"Error: Unable to write decrypted text to file '{output_file}'.")

    else:
        print("Invalid action. Please choose 'generate', 'encrypt', or 'decrypt'.")

if __name__ == "__main__":
    main()
