from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dsa, rsa, padding
import os
import time

# Constants
SMALL_FILE_SIZE = 1024  # 1 KB
LARGE_FILE_SIZE = SMALL_FILE_SIZE * SMALL_FILE_SIZE * 10  # 10 MB

# Generate random data for the files
small_data = os.urandom(SMALL_FILE_SIZE)
large_data = os.urandom(LARGE_FILE_SIZE)

def key_generation_aes(key_size):
    start_time = time.time()
    key = os.urandom(key_size//8) #converting bits to bytes
    key_generation_time = time.time() - start_time
    return key, key_generation_time

# AES CBC encryption and decryption
def aes(key, data, mode):
    start_time = time.time()
    iv = os.urandom(16)
    if(mode == "CBC"):
        pass_mode = modes.CBC(iv)
    elif(mode == "CTR"):
        pass_mode = modes.CTR(iv)
    cipher = Cipher(algorithms.AES(key), pass_mode, backend=default_backend())    
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    encryption_time = time.time()-start_time
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    decryption_time = time.time()-encryption_time
    assert decrypted_data == data  # Check correctness of decryption
    return encryption_time, decryption_time

# # AES CTR encryption and decryption
# def aes_ctr(key, data):
#     start_time = time.time()
#     nonce = os.urandom(16)
#     cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
#     encryptor = cipher.encryptor()
#     encrypted_data = encryptor.update(data) + encryptor.finalize()
#     encryption_time = time.time()-start_time
#     decryptor = cipher.decryptor()
#     decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
#     decryption_time = time.time()-encryption_time
#     assert decrypted_data == data  # Check correctness of decryption
#     return encryption_time, decryption_time

# Generate a new AES key and perform encryption and decryption
def aes_exp(data, key_size, mode):
    key, key_generation_time = key_generation_aes(key_size)
    # measure the time it takes
    encryption_time, decryption_time = aes(key, data, mode)
    # Check the encryption and decryption speeds
    encryption_speed =  len(data)/ encryption_time
    decryption_speed = len(data) / decryption_time
    print(f"\nAES with key size: {key_size}-bit, mode : {mode} and file size: {len(data)}")
    print(f"\tKey generation time: {key_generation_time} s")
    print(f"\tEncryption time: {encryption_time} s ({encryption_speed} bytes/s)")
    print(f"\tDecryption time: {decryption_time} s ({decryption_speed} bytes/s)")

# Perform the experiments for AES (a)-(c).
print("\n\nRunning AES Experiments\n")
aes_exp(small_data, 128, "CBC") #128 bit key, AES, CBS Mode, small file
aes_exp(large_data, 128, "CBC") #128 bit key, AES, CBS Mode, large file
aes_exp(small_data, 128, "CTR") #128 bit key, AES, CTR Mode, small file
aes_exp(large_data, 128, "CTR") #128 bit key, AES, CTR Mode, large file
aes_exp(small_data, 256, "CTR") #128 bit key, AES, CTR Mode, small file
aes_exp(large_data, 256, "CTR") #256 bit key, AES, CTR Mode, large file


#Implementing RSA
with open("small_file.txt", "wb") as f:
    f.write(os.urandom(1024))
with open("large_file.txt", "wb") as f:
    f.write(os.urandom(1024 * 1024))

def key_generation_rsa(key_size):
    start_time = time.monotonic()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    public_key = private_key.public_key()
    key_gen_time = time.monotonic() - start_time
    return private_key, public_key, key_gen_time

def rsa_exp(input_file, output_file, key_size):
    print("\n\nRSA with key size: {}-bit and File Size :{}".format(key_size, os.path.getsize((input_file))))
    private_key, public_key, key_generation_time = key_generation_rsa(key_size)
    print(f"\tKey generation time: {key_generation_time} s")
    encryption_time = 0
    decryption_time = 0
    with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
        chunk_size = 100
        plaintext_array = bytearray()
        while True:
            chunk = f_in.read(chunk_size)
            if not chunk:
                break
            start_time = time.monotonic()
            ciphertext = public_key.encrypt(chunk, padding.PKCS1v15())
            encryption_time+= time.monotonic() - start_time
            start_time = time.monotonic()
            plaintext = private_key.decrypt(ciphertext, padding.PKCS1v15())
            decryption_time+= time.monotonic() - start_time
            plaintext_array += plaintext
        encryption_speed = os.path.getsize(input_file)/ encryption_time
        decryption_speed = os.path.getsize(input_file)/ decryption_time
        print(f"\tEncryption time: {encryption_time} s")
        print(f"\tDecryption time: {decryption_time} s")
        print(f"\tEncryption speed per byte: {encryption_speed} s")
        print(f"\tDecryption speed per byte: {decryption_speed} s")

        f_out.write(plaintext_array)

    with open(input_file, "rb") as f_in, open(output_file, "rb") as f_out:
        plaintext = f_out.read()

    assert os.path.getsize(input_file) == len(plaintext)

# Perform the experiments for RSA (d)-(e).
print("\n\nRunning RSA Experiments\n\n")
rsa_exp("small_file.txt","small_file_encrypted.txt", 2048)
rsa_exp("large_file.txt","large_file_encrypted.txt", 2048)
rsa_exp("small_file.txt","small_file_encrypted.txt", 3072)
rsa_exp("large_file.txt","large_file_encrypted.txt", 3072)


#Implementing HASHING

print("\n\nRunning HASH Experiments\n\n")

#Hashing of each file
with open('small_file.txt', 'wb') as f:
    f.write(os.urandom(1024))

with open('large_file.txt', 'wb') as f:
    f.write(os.urandom(1024 * 1024 * 10))

# Measure the time taken to compute the hashes
def hash_exp(hash_algorithm):
    hash_name = hash_algorithm.name
    hash_func = hashes.Hash(hash_algorithm, backend=default_backend())

    start_time = time.time()
    with open('small_file.txt', 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    small_file_hash = hash_func.finalize()
    small_file_time = time.time()-start_time

    hash_func = hashes.Hash(hash_algorithm, backend=default_backend())
    start_time = time.time()
    with open('large_file.txt', 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    large_file_hash = hash_func.finalize()
    large_file_time = time.time() - start_time

    total_time = small_file_time + large_file_time
    per_byte_time_small = total_time / 1024
    per_byte_time_large = total_time / (1024 * 1024)

    print(f'\nComputing timings for hash: ', hash_name)
    print(f'\tTotal time taken for small file: {small_file_time}s')
    print(f'\tTotal time taken for large file: {large_file_time}s')
    print(f'\tTotal time taken for both the files: {total_time}s')
    print(f'\tPer-byte time for small file: {per_byte_time_small}s')
    print(f'\tPer-byte time for large file: {per_byte_time_large}s')

hash_algorithms = [hashes.SHA256(), hashes.SHA512(), hashes.SHA3_256()]
for hash in hash_algorithms:
    hash_exp(hash)

#Implementing DSA Experiments
def generate_key_pair(key_size):
    start = time.time()
    private_key = dsa.generate_private_key(key_size=key_size)
    end = time.time()
    key_gen_time = end - start
    public_key = private_key.public_key()
    return private_key, public_key, key_gen_time


def sign_file(file_path, private_key):
    with open(file_path, "rb") as f:
        data = f.read()
    start = time.time()
    signature = private_key.sign(data, hashes.SHA256())
    end = time.time()
    sign_time = end - start
    return signature, sign_time


def verify_file(file_path, public_key, signature):
    with open(file_path, "rb") as f:
        data = f.read()
    start = time.time()
    try:
        public_key.verify(signature, data, hashes.SHA256())
        valid = True
    except:
        valid = False
    end = time.time()
    verify_time = end - start
    return valid, verify_time


def run_experiment(key_size):
    print(f"\n\nCalculating times for {key_size}-bit DSA key\n")
    small_file_name = "1KB_file.txt"
    large_file_name = "10MB_file.txt"
    small_data = os.urandom(1024)
    large_data = os.urandom(1024 * 1024 * 10)
    with open(small_file_name, "wb") as f:
        f.write(small_data)
    with open(large_file_name, "wb") as f:
        f.write(large_data)
    # generate key pair
    private_key, public_key, key_gen_time = generate_key_pair(key_size)

    # sign files
    signature_small, sign_time_small = sign_file("1KB_file.txt", private_key)
    signature_large, sign_time_large = sign_file("10MB_file.txt", private_key)

    # verify files
    valid_small, verify_time_small = verify_file("1KB_file.txt", public_key, signature_small)
    assert(valid_small)
    valid_large, verify_time_large = verify_file("10MB_file.txt", public_key, signature_large)
    assert(valid_large)

    # compute per-byte signing and verification time
    per_byte_sign_time_small = sign_time_small / 1024
    per_byte_sign_time_large = sign_time_large / (1024 * 1024 * 10)
    per_byte_verify_time_small = verify_time_small / 1024
    per_byte_verify_time_large = verify_time_large / (1024 * 1024 * 10)

    # print results
    print(f"\tKey generation time for {key_size}-bit DSA key: {key_gen_time}s")
    print(f"\tSignature time for small file using {key_size}-bit DSA key: {sign_time_small}s")
    print(f"\tSignature time for large file using {key_size}-bit DSA key: {sign_time_large}s")
    print(f"\tVerification time for small file using {key_size}-bit DSA key: {verify_time_small}s")
    print(f"\tVerification time for large file using {key_size}-bit DSA key: {verify_time_large}s")
    print(f"\tPer-byte signature time for small file using {key_size}-bit DSA key: {per_byte_sign_time_small}s")
    print(f"\tPer-byte signature time for large file using {key_size}-bit DSA key: {per_byte_sign_time_large}s")
    print(f"\tPer-byte verification time for small file using {key_size}-bit DSA key: {per_byte_verify_time_small}s")
    print(f"\tPer-byte verification time for large file using {key_size}-bit DSA key: {per_byte_verify_time_large}s")

print("\n\nRunning DSA Experiments")
run_experiment(2048)
run_experiment(3072)