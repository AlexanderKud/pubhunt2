import ecdsa
from ecdsa.numbertheory import inverse_mod
import requests

# SECP256K1 parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (Gx, Gy)

# Elliptic curve point addition and doubling
def mod_inverse(k, p):
    return inverse_mod(k, p)

def ec_add(P, Q, p):
    if P == (0, 0): return Q
    if Q == (0, 0): return P
    if P == Q:
        l = (3 * P[0]**2 + A) * mod_inverse(2 * P[1], p) % p
    else:
        l = (Q[1] - P[1]) * mod_inverse(Q[0] - P[0], p) % p
    x_r = (l**2 - P[0] - Q[0]) % p
    y_r = (l * (P[0] - x_r) - P[1]) % p
    return (x_r, y_r)

def scalar_mult(k, P, p):
    R = (0, 0)
    Q = P
    while k:
        if k & 1:
            R = ec_add(R, Q, p)
        Q = ec_add(Q, Q, p)
        k >>= 1
    return R

def diagonal_transform(pub_key):
    """Experimental transformation to find private key from public key."""
    x, y = pub_key
    return ((x - y) ** 3) % N if x > y else ((y - x) ** 3) % N

def send_telegram_message(message):
    """Sends a message to a Telegram bot."""
    bot_token = "YOUR_BOT_TOKEN"
    chat_id = "YOUR_CHAT_ID"
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    requests.post(url, data={"chat_id": chat_id, "text": message})

# Input: Uncompressed public key (hex format)
input_public_key = "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"

# Extract x-coordinate
x_coord = int(input_public_key[2:66], 16)

# Initialize private key with x-coordinate
private = x_coord

for i in range(1000000000):  # Limit iterations
    public = scalar_mult(private, G, P)
    recovered_k = diagonal_transform(public)
    print(f"Iteration {i}: Private = {private}, Recovered = {recovered_k}")
    
    # Check if recovered public key matches input public key
    if scalar_mult(recovered_k, G, P) == (int(input_public_key[2:66], 16), int(input_public_key[66:], 16)):
        message = f"Success: Recovered Private Key = {recovered_k}"
        print(message)
        send_telegram_message(message)
        break
    
    private = recovered_k
