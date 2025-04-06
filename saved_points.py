import ecdsa
import hashlib
import random

with open("pubs.txt", "r") as f:
    pub_keys = {line.strip() for line in f}

# secp256k1 parameters
def int_to_uncompressed_pubkey(private_key_int):
    # Convert integer to 32-byte hex
    private_key_bytes = private_key_int.to_bytes(32, byteorder='big')
    
    # Generate public key using secp256k1
    sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    
    # Get X and Y coordinates
    pub_x = int.from_bytes(vk.to_string()[:32], byteorder='big')
    pub_y = int.from_bytes(vk.to_string()[32:], byteorder='big')
    
    # Get the uncompressed public key (prefix 0x04 + X + Y coordinates)
    public_key_bytes = b'\x04' + vk.to_string()
    
    # Save pub_x - private_key_int to file
    with open("saved_step.txt", "a") as f:
        if pub_x > private_key_int:
            f.write(f"{str(pub_x - private_key_int)}\n")
        else:
            f.write(f"{str(pub_x + private_key_int)}\n")
    
    return public_key_bytes.hex(), pub_x, pub_y

# Example usage
for i in range(100000):
    private_key_int = random.randint(2**245, 2**256)
    uncompressed_pubkey, pub_x, pub_y = int_to_uncompressed_pubkey(private_key_int)
    if uncompressed_pubkey in pub_keys:
        print("Uncompressed Public Key:", uncompressed_pubkey)
        print(private_key_int)
        # print("Public Key X:", pub_x)
        # print("Public Key Y:", pub_y)
