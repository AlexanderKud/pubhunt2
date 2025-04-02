import ecdsa
from ecdsa.numbertheory import inverse_mod
import requests

# SECP256K1 პარამეტრები
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (Gx, Gy)

# ელიფსური მრუდის წერტილების ოპერაციები
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

def send_telegram_message(message):
    """შეტყობინების გაგზავნა Telegram-ზე."""
    bot_token = "YOUR_BOT_TOKEN"
    chat_id = "YOUR_CHAT_ID"
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    requests.post(url, data={"chat_id": chat_id, "text": message})

# შეყვანილი საჯარო გასაღები (Uncompressed)
input_public_key = input("Enter uncompressed public key: ")
modified_public = input_public_key[2:]

# x კოორდინატის ამოღება
x_coord = int(modified_public[:64], 16)

# საჯარო გასაღებების ბაზის წაკითხვა
with open("pubs.txt", "r") as f:
    pub_keys = {line.strip() for line in f}

# საძიებო ალგორითმი
i = 1
anof = 1

while True:
    print(f"Iteration {i}")
    
    key = modified_public[:i]
    try:
        private = int(key, 16) % N
    except ValueError:
        print("Error converting key segment.")
        break

    private_key = anof % N
    print(f"Generated Private Key: {private_key}")

    public = scalar_mult(private_key, G, P)
    public_hex = f"04{public[0]:064x}{public[1]:064x}"
    print(f"Generated Public Key: {public_hex}")

    if public_hex in pub_keys:
        message = f"Success: Recovered Private Key = {private_key}"
        print(message)
        send_telegram_message(message)
        break

    i += 1
    anof += private
