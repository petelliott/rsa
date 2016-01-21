import random
import math


def rand(size):
    return random.SystemRandom().getrandbits(size)


def is_probable_prime(n):
    _mrpt_num_trials = 5
    assert n >= 2

    if n == 2:
        return True

    if n % 2 == 0:
        return False
    s = 0
    d = n-1
    while True:
        quotient, remainder = divmod(d, 2)
        if remainder == 1:
            break
        s += 1
        d = quotient
    assert(2**s * d == n-1)

    def try_composite(a):
        if pow(a, d, n) == 1:
            return False
        for i in range(s):
            if pow(a, 2**i * d, n) == n-1:
                return False
        return True

    for i in range(_mrpt_num_trials):
        a = random.randrange(2, n)
        if try_composite(a):
            return False

    return True


def genPrime(size):
    while True:
        num = rand(size)
        if is_probable_prime(num):
            return num


def euclid(a, b):
    a = abs(a)
    b = abs(b)
    if a < b:
        a, b = b, a
    while b != 0:
        a, b = b, a % b
    return a


def coPrime(a,b):
    if euclid(a,b) == 1:
        return True
    else:
        return False


def extendedEuclid(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, y, x = extendedEuclid(b % a, a)
        return g, x - (b // a) * y, y


def modInv(a, m):
    if coPrime(a, m):
        linearCombination = extendedEuclid(a, m)
        return linearCombination[1] % m
    else:
        return 0


def randCoprime(key_size, num):
    while True:
        out = rand(key_size)
        if coPrime(out, num):
            return out


class KeyFactory:
    def __init__(self, key_size):
        prime1 = genPrime(key_size)
        prime2 = genPrime(key_size)

        n = prime1*prime2
        totient = (prime1-1) * ( prime2-1)
        e = randCoprime(key_size, totient)
        d = modInv(e, totient)

        self.modulos = n
        self.pub_exp = e
        self.priv_exp = d


class PrivKey:
    def __init__(self,key_factory):
        self.exponent = key_factory.priv_exp
        self.modulos = key_factory.modulos

    def decrypt(self, data):
        return pow(data, self.exponent, self.modulos)


class PubKey:
    def __init__(self, key_factory):
        self.exponent = key_factory.pub_exp
        self.modulos = key_factory.modulos

    def encrypt(self, data):
        return pow(data, self.exponent, self.modulos)
