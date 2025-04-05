from ecdsa import SECP256k1, ellipticcurve
import random

# ა) განსაზღვრეთ G წერტილი და მრუდის პარამეტრები
G = SECP256k1.generator
n = SECP256k1.order

# ბ) შექმენით pub წერტილი 
# pub = (46833799212576611471711417854818141128240043280360231002189938627535641370294, 33454781559405909841731692443380420218121109572881027288991311028992835919199)
# წერტილის შექმნა
pub_x = 46833799212576611471711417854818141128240043280360231002189938627535641370294
pub_y = 33454781559405909841731692443380420218121109572881027288991311028992835919199
curve = SECP256k1.curve
pub = ellipticcurve.Point(curve, pub_x, pub_y)

# გ) "მიმატება" G-ს იტერაციულად
k = 1
while True:
    Q = pub + k * G
    if Q.x() < 47833799212576611471711417854818141128240043280360231002189938627535641370294 and Q.x() > 45833799212576611471711417854818141128240043280360231002189938627535641370294: 
        q_x = Q.x()
        pub_x_val = pub.x()  # ესეც საჭიროა

        # print(f"Iteration {k}: Q = ({Q.x()}, {Q.y()})")
        predict = pub_x_val - q_x
        piv = predict + k
        res = piv * G
        # print(f"{res} || {pub}")

        if res.x() == pub.x():
            print("Found!")
            print(piv)
            break 
        # print(Q.x())
    
    # შეამოწმეთ, Q == pub?
    if k % n == 0:  # მხოლოდ k = 0, n, 2n, ...
        print(f"Found match at k = {k} (Q = pub)")
        break
    
    k = random.randint(1, 2**256)
