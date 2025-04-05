import ecdsa
import math
import threading
from concurrent.futures import ThreadPoolExecutor

# SECP256K1 Curve Parameters
N = ecdsa.SECP256k1.order
G = ecdsa.SECP256k1.generator

def hex_to_xy(hex_key):
    """Extracts X, Y coordinates from an uncompressed hex public key."""
    if not hex_key.startswith("04") or len(hex_key) != 130:
        return None, None  # Invalid key format

    x_hex = hex_key[2:66]  # Extract X
    y_hex = hex_key[66:]   # Extract Y
    return int(x_hex, 16), int(y_hex, 16)

def logarithmic_transform(pub_key):
    """Applies a logarithmic transformation to the public key coordinates."""
    x, y = pub_key
    # if x > 0 and y > 0:
    #     return (int(math.log2(x) + math.log2(y))) % N
    if x > y:
        return ((x + y) * x) % N
    else:
        return ((y + x) * y) % N
    # return None 

def generate_public_key(private_key):
    """Computes the public key from a private key."""
    public_point = private_key * G
    return public_point.x(), public_point.y()

def kaliski_swaps(x: int, p: int, n: int):
    """Computes modular inverse using Kaliski’s method with swaps."""
    u, v, r, s = p, x, 0, 1

    for _ in range(2 * n):
        if v == 0:
            r *= 2
            continue

        swap = False
        if u % 2 == 0 or (u % 2 == 1 and u > v):
            u, v = v, u
            r, s = s, r
            swap = True

        if v > u:
            v -= u
            s += r
            v //= 2
            r *= 2

        if swap:
            u, v = v, u
            r, s = s, r

    return u, v, r, s

def recover_private_key(pub_x, pub_y):
    """Attempts to recover a private key from a given public key."""
    try:
        transformed_value = logarithmic_transform((pub_x, pub_y))
        if transformed_value is None:
            return None

        diff = abs(transformed_value)

        # Attempting to recover the private key
        for i in range(100000):
            test_key = pub_x - (diff * i)
            
            if 0 < test_key < N:  # Ensure valid private key range
                # Apply modular inverse using Kaliski’s method
                _, _, inv_key, _ = kaliski_swaps(test_key, N, 256)
                return hex(inv_key)  # Return hex format

    except Exception as e:
        print(f"Error processing key ({pub_x}, {pub_y}): {e}")
    return None

def process_keys():
    """Processes all public keys in parallel using multi-threading."""
    with open("pubs.txt", "r") as f:
        public_keys = [line.strip() for line in f.readlines()]

    results = []
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = []
        for line in public_keys:
            # print(line)
            pub_x, pub_y = hex_to_xy(line)
            # print(pub_x)
            if pub_x is not None and pub_y is not None:
                futures.append(executor.submit(recover_private_key, pub_x, pub_y))

        for future in futures:
            result = future.result()
            if result:
                results.append(result)

    # Save recovered private keys
    with open("recovered_priv_keys.txt", "w") as f_out:
        for key in results:
            if key != "0x1":
                f_out.write(f"Recovered Private Key: {key}\n")
                print(f"Recovered Private Key: {key}")

if __name__ == "__main__":
    process_keys()
