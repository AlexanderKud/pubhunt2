import ecdsa
from ecdsa.numbertheory import inverse_mod
import requests
import random

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
    un_modified_k = k
    while k:
        steps = []
        if k & 1:
            R = ec_add(R, Q, p)
            steps.append(R[0] + un_modified_k)
        Q = ec_add(Q, Q, p)
        steps.append(Q[0] + un_modified_k)
        k >>= 1
    return R, steps

# საჯარო გასაღებების წაკითხვა ფაილიდან
with open("pubs.txt", "r") as f:
    pub_keys = {line.strip() for line in f}

for input_pub_keys in pub_keys:
    # print(input_pub_keys)
    # from u.pub take x coordinate
    p_g_x = int(input_pub_keys[2:66], 16)
    p_g_y = int(input_pub_keys[66:], 16)

    private = (p_g_x + p_g_y) % N-1

# for i in range(200000):

#     private = random.randint(1, N)

    # from x generating public and all steps too and returning both
    pub, steps = scalar_mult(private, G, P)

    # calculate private - for step in steps
    for step in steps:
        predict_key = ((step + (Gx + Gy)) * Gx) % N
        # print(predict_key)
        # try if predict_key match to input_pub_keys
        public, second_steps = scalar_mult(predict_key, G, P)
        public_hex = f"04{public[0]:064x}{public[1]:064x}"
        # print(public_hex)

        if public_hex in pub_keys:
            message = f"Success: Recovered Private Key = {predict_key}"
            # print(message)
            exit()

        for step in steps:
            for i in range(len(steps)):
                step = step + (i * Gx) % N
                print(step)
                public, second_steps = scalar_mult(step, G, P)
                public_hex = f"04{public[0]:064x}{public[1]:064x}"
                # print(public_hex)

                if public_hex in pub_keys:
                    message = f"Success: Recovered Private Key = {predict_key}"
                    # print(message)
                    exit()
