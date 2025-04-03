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

# ელიფსური მრუდის ოპერაციები
def mod_inverse(k, p):
    return inverse_mod(k, p)

def ec_add(P, Q, p):
    if P == (0, 0): return Q
    if Q == (0, 0): return P
    if P == Q:
        l = (3 * P[0]**2 + A) * mod_inverse(2 * P[1], p) % p
    else:
        if P[0] == Q[0]: return (0, 0)  # წერტილების განუსაზღვრელი ჯამი
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

# საჯარო გასაღებების წაკითხვა ფაილიდან
with open("pubs.txt", "r") as f:
    pub_keys = {line.strip() for line in f}

# საძიებო ალგორითმი
for input_public_key in pub_keys:
    modified_public = input_public_key[2:]  # '04'-ის მოშორება

    # ყველა შესაძლო substring-ის შექმნა
    for start in range(len(modified_public)):
        for end in range(start + 1, len(modified_public) + 1):
            key_segment = modified_public[start:end]
            priv = int(key_segment, 16) % N
            # print(key_segment)

            for j in range(10000):

                try:
                    # priv = int(key_segment, 16) % N
                    private_key_candidate = (priv ** 3) % N
                    # print(private_key_candidate)

                except ValueError:
                    continue  # არასწორი 16-ობითი რიცხვი

                # შესაბამისი საჯარო გასაღების გამოთვლა
                public = scalar_mult(private_key_candidate, G, P)
                public_hex = f"04{public[0]:064x}{public[1]:064x}"
                # print(private_key_candidate)

                if public_hex in pub_keys:
                    message = f"Success: Recovered Private Key = {private_key_candidate}"
                    print(message)
                    send_telegram_message(message)
                    exit()  # გავაჩეროთ კოდი, თუ ვიპოვეთ გასაღები
                
                priv = private_key_candidate
