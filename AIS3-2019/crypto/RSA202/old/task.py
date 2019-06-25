from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, isPrime, inverse 
from secret import p, r, FLAG1, FLAG2

assert ((p-1) % r)**2 + ((r**5 - 1) % p)**2 == 0
assert isPrime(p) + isPrime(r) == 2

def next_prime(num):
    while True :
        num +=1
        if isPrime(num):
            return num

e = 65537

n1 = r * next_prime(r)
n2 = p * getPrime(1024)

enc1 = pow(FLAG1, e, n1)
enc2 = pow(FLAG2, e, n2)

print('(enc1,n1) =', (enc1,n1) )
print('(enc2,n2) =', (enc2,n2) )