from ecdsa import SECP256k1, ellipticcurve
import random

# ა) განსაზღვრეთ G წერტილი და მრუდის პარამეტრები
G = SECP256k1.generator
n = SECP256k1.order
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ბ) შექმენით pub წერტილი 
# pub = (46833799212576611471711417854818141128240043280360231002189938627535641370294, 33454781559405909841731692443380420218121109572881027288991311028992835919199)
# წერტილის შექმნა
pub_x = 46833799212576611471711417854818141128240043280360231002189938627535641370294
pub_y = 33454781559405909841731692443380420218121109572881027288991311028992835919199
curve = SECP256k1.curve
pub = ellipticcurve.Point(curve, pub_x, pub_y)

# საჯარო გასაღებების წაკითხვა ფაილიდან
with open("pubs.txt", "r") as f:
    pub_keys = {line.strip() for line in f}

# გ) "მიმატება" G-ს იტერაციულად
k = 1
jaco = 55066263022277343669578718895168534326250603453777594175500187360389116729240
while True:
    Q = pub + k * G
    # if Q.x() < 46833899212576611471711417854818141128240043280360231002189938627535641370294 and Q.x() > 46833699212576611471711417854818141128240043280360231002189938627535641370294:
    if Q.x():
        q_x = Q.x()
        pub_x_val = pub.x()  # ესეც საჭიროა

        # print(f"Iteration {k}: Q = ({Q.x()}, {Q.y()})")
        # print(k)

        if pub_x_val > q_x:
            predict = pub_x_val - q_x
        else:
            predict = q_x - pub_x_val
        piv = (predict + k) % N
        # print(f"{k} = {piv}")
        res = piv * G
        # print(f"{res} || {pub}")
        public = f"04{res.x():064x}{res.y():064x}"
        # print(piv, public)

        if public in pub_keys:
            message = f"Success: Recovered Private Key = {piv}"
            print(message)
        # print(Q.x())
    
    # შეამოწმეთ, Q == pub?
    if k % n == 0:  # მხოლოდ k = 0, n, 2n, ...
        print(f"Found match at k = {k} (Q = pub)")
    
    k = (k + jaco) % N 
    # print(k)