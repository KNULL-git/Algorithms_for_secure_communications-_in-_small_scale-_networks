#!pip install reedsolo
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import GCM
import reedsolo
import time
def add_reed_solomon_error_correction(data):
    rs = reedsolo.RSCodec(10)  # Initialize RSCodec with the desired number of error correction bytes
    encoded_data = rs.encode(data)
    return encoded_data

def remove_reed_solomon_error_correction(data):
    rs = reedsolo.RSCodec(10)
    decoded_data = rs.decode(data)[0]
    return decoded_data

def calculate_checksum(data):
    checksum = hashlib.sha256(data).digest()
    return checksum

def verify_checksum(data, checksum):
    calculated_checksum = hashlib.sha256(data).digest()
    return calculated_checksum == checksum

def aes_gcm_authenticated_encryption(key, iv, associated_data, plaintext):
    aes_gcm_encryptor = Cipher(AES(key), GCM(iv)).encryptor()
    aes_gcm_encryptor.authenticate_additional_data(associated_data)
    ciphertext = aes_gcm_encryptor.update(plaintext) + aes_gcm_encryptor.finalize()
    auth_tag = aes_gcm_encryptor.tag
    return ciphertext, auth_tag

def aes_gcm_authenticated_decryption(key, iv, associated_data, ciphertext, auth_tag):
    aes_gcm_decryptor = Cipher(AES(key), GCM(iv, auth_tag)).decryptor()
    aes_gcm_decryptor.authenticate_additional_data(associated_data)
    plaintext = aes_gcm_decryptor.update(ciphertext) + aes_gcm_decryptor.finalize()
    return plaintext

def calculate_ber(original_data, recovered_data):
    num_bits = len(original_data) * 8
    num_errors = sum(a != b for a, b in zip(original_data, recovered_data))
    ber = num_errors / num_bits
    return ber, num_errors

def calculate_fer(num_errors):
    fer = 1 if num_errors > 0 else 0
    return fer

def calculate_overhead(original_data, encoded_data):
    original_size = len(original_data)
    encoded_size = len(encoded_data)
    overhead = encoded_size - original_size
    return overhead

# Generate a random 256-bit symmetric key
key = os.urandom(32)

# Generate a random 96-bit initialization vector (IV)
iv = os.urandom(12)

# Our message to be kept confidential
with open("test_data_512_kb.bin", "rb") as f:
    plaintext = f.read()

# Associated data (optional)
associated_data = b"Context of using AES GCM"

start_time = time.time()
# Add Reed-Solomon error correction to the plaintext
encoded_plaintext = add_reed_solomon_error_correction(plaintext)

# Calculate checksum of the plaintext
checksum = calculate_checksum(encoded_plaintext)

# Encrypt the plaintext using AES-GCM
ciphertext, auth_tag = aes_gcm_authenticated_encryption(key, iv, associated_data, encoded_plaintext)
encryption_time = time.time() - start_time
start_time = time.time()
# Decrypt and authenticate the ciphertext
recovered_encoded_plaintext = aes_gcm_authenticated_decryption(key, iv, associated_data, ciphertext, auth_tag)

# Verify the correctness of encryption and decryption
assert verify_checksum(recovered_encoded_plaintext, checksum), "Checksum verification failed!"

# Remove Reed-Solomon error correction from the recovered plaintext
recovered_plaintext = remove_reed_solomon_error_correction(recovered_encoded_plaintext)
decryption_time = time.time() - start_time
# Convert byte strings to regular strings
plaintext_str = plaintext
recovered_plaintext_str = recovered_plaintext

# Calculate BER and FER
ber, num_errors = calculate_ber(encoded_plaintext, recovered_encoded_plaintext)
fer = calculate_fer(num_errors)

# Calculate overhead
overhead = calculate_overhead(plaintext, encoded_plaintext)

# Display metrics
def display_metrics():
    print("=== Performance Metrics ===")
    #print(f"Original Plaintext: {plaintext_str}")
    #print(f"Recovered Plaintext: {recovered_plaintext_str}")
    print(f"Encryption Time: {encryption_time:.6f} seconds")
    print(f"Decryption Time: {decryption_time:.6f} seconds")
    print(f"Bit Error Rate (BER): {ber:.10f}")
    print(f"Number of Bit Errors: {num_errors}")
    print(f"Frame Error Rate (FER): {fer}")
    print(f"Overhead (bytes): {overhead}")
    print(f"Original Size (bytes): {len(plaintext)}")
    print(f"Encoded Size (bytes): {len(encoded_plaintext)}")

# Display all metrics
display_metrics()
