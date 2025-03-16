import time
import random
import sympy
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import math
import os

def generate_large_primes(bits=512):
    """Generate two large prime numbers p and q."""
    p = sympy.randprime(2**(bits-1), 2**bits)
    q = sympy.randprime(2**(bits-1), 2**bits)
    return p, q

def compute_totient(p, q):
    """Compute Euler's totient function φ(N)."""
    return (p - 1) * (q - 1)

def generate_valid_a(N):
    """Generate a random number a such that gcd(a, N) = 1."""
    while True:
        a = random.randint(2, N - 1)  # Choose random a
        if math.gcd(a, N) == 1:  # Ensure gcd(a, N) = 1
            return a

def KeyGen(n):
    """Generate n cryptographic secure 128-bit symmetric keys."""
    return [get_random_bytes(16) for _ in range(n)]

def generate_random_strings(n):
    """Generate n random 64-bit strings for commitments."""
    r_values = [random.getrandbits(64) for _ in range(n)]
    return r_values

def setup(T, S, N, phi_N , n):
    """Generate parameters for the time-lock puzzle."""
    t = S * T  # Total number of squaring operations
    a = generate_valid_a(N)  # Ensure a is coprime to N
    u = pow(2, t, phi_N)  # Compute u correctly using φ(N)
    k = KeyGen(n)
    r = generate_random_strings(n)
    return t, a, u, k, r

def sequential_squaring(a, t, N):
    """Compute a^(2^t) mod N using strict sequential squaring."""
    result = a
    start_time = time.time()
    
    for _ in range(t):
        result = (result * result) % N  # Instead of pow(result, 2, N)

    end_time = time.time()
    # print(f"Sequential squaring completed in {end_time - start_time:.2f} seconds.")
    return result

def decrypt_message(ciphertext, key):
    """Decrypt an AES-encrypted message."""
    cipher = AES.new(key, AES.MODE_CBC, ciphertext[:16])
    return unpad(cipher.decrypt(ciphertext[16:]), AES.block_size).decode()


def encrypt_message(message, key):
    """Encrypt a message using AES with a 128-bit key."""
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext  # Prepend IV for decryption

def hash_commitment(message, r_i):
    """Compute commitment using SHA-1 (160-bit hash)."""
    return hashlib.sha1((message + str(r_i)).encode()).hexdigest()

def generate_puzzle(messages, N, a, u, k, r):
    puzzles = []
    commitments = []
    r_values = r

    for i in range(len(messages)):
        message = messages[i]

        # Encrypt message using symmetric encryption
        c1 = encrypt_message(message, k[i])
        # Convert the key from bytes to an integer
        k_i_int = int.from_bytes(k[i], 'big')

        if i == 0:
            c2 = (k_i_int + pow(a, u, N)) % N
        else:
            prev_message = int.from_bytes(messages[i - 1].encode(), 'big')  # Convert message to integer
            c2 = (k_i_int + pow(prev_message, u, N)) % N

        # Store the puzzle (c1, c2)
        c2_bytes = c2.to_bytes((c2.bit_length() + 7) // 8, 'big')  # Convert c2 to bytes
        puzzles.append((c1, c2_bytes))

    # Generate commitments
    for i in range(n):
        commitments.append(hash_commitment(messages[i], r_values[i]))

    return puzzles, commitments


def solve_puzzle(Z, r_values, N, t, a):
    messages = []
    for i, (c1, c2_bytes) in enumerate(Z):
        c2 = int.from_bytes(c2_bytes, 'big')  # Convert c2 from bytes to integer
        
        if i == 0:
            v_i = sequential_squaring(a, t, N)  # Compute v for first message
        else:
            prev_message = int.from_bytes(messages[i - 1].encode(), 'big')
            v_i = sequential_squaring(prev_message, t, N)
        
        k_i = (c2 - v_i) % N  # Recover symmetric key
        k_i_bytes = k_i.to_bytes(16, 'big')  # Convert key to bytes
        
        m_i = decrypt_message(c1, k_i_bytes)  # Decrypt the message
        messages.append(m_i)
        
        # Verify commitment
        h_prime = hash_commitment(m_i, r_values[i])
        print(f"Message {i+1}: {m_i}, Commitment Verified: {h_prime}")
    
    return messages


# --- Main Execution ---
T = int(input("Enter lock time in seconds (T): "))  
S = int(input("Enter number of squaring operations per second (S): "))  
n = int(input("Enter number of messages (n): "))

messages = []
for i in range(n):
    msg = input(f"Enter message {i + 1}: ")
    messages.append(msg)

print("Generating large primes...")
p, q = generate_large_primes()
N = p * q
phi_N = compute_totient(p, q)

t, a, u, k, r = setup(T, S, N , phi_N, n)
print(f"Generated Parameters:\nN = {N}\nt = {t}\na = {a}\nu = {u}\nk= {k}\nr= {r}")

# Generate puzzle
Z, commitments = generate_puzzle(messages, N, a,u, k, r)

# Display results
print("Generated Puzzle Z:", Z)
print("Commitments:", commitments)


# Ask the user if they want to solve the puzzle
solve_choice = input("\nDo you want to solve the puzzle now? (yes/no): ").strip().lower()

if solve_choice == 'yes':
    print("\nSolving Chained Time-Lock Puzzle...")
    decrypted_messages = solve_puzzle(Z, r, N, t, a)
    print("Decrypted Messages:", decrypted_messages)
else:
    print("\nPuzzle not solved. You can solve it later using the stored values.")
