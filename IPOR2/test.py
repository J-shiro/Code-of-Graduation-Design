import random
import hmac 
import hashlib
import os

def find_generator(p):
    # Z_p* is cyclic if p is 2, 4, p^k, or 2*p^k where p is an odd prime.
    # Here, we assume p is an odd prime for simplicity.
    for g in range(2, p):
        if pow(g, (p - 1) // 2, p) != 1 and pow(g, (p - 1) // 3, p) != 1:
            return g
    return None

def random_high_order_element(p):
    generator = find_generator(p)
    if generator is None:
        print("Cannot find a generator for Z_{}*".format(p))
        return None
    while True:
        u = random.randint(2, p - 1)
        if pow(generator, u, p) != 1:
            return u

def PHI_prf_sk(i, sk):
        ans_bytes = hmac.new(sk, i.to_bytes((i.bit_length() + 7) // 8, 'big'), hashlib.sha256).digest()
        ans = int.from_bytes(ans_bytes, byteorder="big")
        return ans

# p = 13  # 这里选择一个素数
p = 129849385948579467943583984504857498674233982
u = random_high_order_element(p)
print("随机初始化的高阶元素 u =", u)

sk = os.urandom(512 // 8)
print(sk)
a = PHI_prf_sk(1, sk)

print(a)
b = PHI_prf_sk(1, sk)

print(b)