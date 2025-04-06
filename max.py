import ecdsa
import hashlib

MAX_PRIV_KEY = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # secp256k1 max

with open("pubs.txt", "r") as f:
    pub_keys = {line.strip() for line in f}

with open("saved_step.txt", "r") as s:
    step_keys = {line.strip() for line in s}

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
    
    return public_key_bytes.hex(), pub_x, pub_y

def main():
    while True:
        for p in pub_keys:
            p = int(p[2:66], 16)
            for l in step_keys:
                l = int(l)
                for j in range(100):
                    if l < p:
                        priv = p - l
                        print(priv)
                    else:
                        priv = l - p
                        print(priv)
                    
                    if priv < 1 or priv > MAX_PRIV_KEY:
                        priv = priv % MAX_PRIV_KEY

                    uncompressed_pubkey, pub_x, pub_y = int_to_uncompressed_pubkey(priv)

                    if uncompressed_pubkey in pub_keys:
                        print(priv)
                    
                    l = pub_x


if __name__ == "__main__":
    main()
