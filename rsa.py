import random
import math
import hashlib


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


def coPrime(a, b):
    if euclid(a, b) == 1:
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


def toInt(text):
    num = 0
    for a, b in enumerate(text):
        num += ord(b) << (a*8)
    return num


def fromInt(num):
    text = ""
    while num > 0:
        text += chr(num & 0xff)
        num = num >> 8
    return text


def sha256(string):
    hash_value = hashlib.sha256(bytes(string, "utf-8")).hexdigest()
    return int(hash_value, 16)


class KeyFactory:
    def __init__(self, key_size):
        prime1 = genPrime(key_size)
        prime2 = genPrime(key_size)

        n = prime1*prime2
        totient = (prime1-1) * (prime2-1)
        d = randCoprime(key_size, totient)
        e = modInv(d, totient)

        self.modulos = n
        self.pub_exp = e
        self.priv_exp = d


class Key:
    def __init__(self, exp, mod):
        self.exponent = exp
        self.modulos = mod

    def crypt(self, data):
        return pow(data, self.exponent, self.modulos)

    def __str__(self):
        return (hex(self.exponent) + "%" + hex(self.modulos)).replace("0x", "")


class PubKey(Key):
    def __init__(self, key_data):
        if type(key_data) is KeyFactory:
            super().__init__(key_data.pub_exp, key_data.modulos)

        elif type(key_data) is str:
            parts = key_data.split("%")
            super().__init__(int(parts[0], 16), int(parts[1], 16))

        else: raise TypeError("can't create a key from this")

    def encrypt(self, data):
        cypher_data = self.crypt(toInt(data))
        return hex(cypher_data).replace("0x", "")

    def verify(self, signature, message):
        hash_value = self.crypt(int(signature, 16))
        return hash_value == sha256(message)


class PrivKey(Key):
    def __init__(self, key_data):
        if type(key_data) is KeyFactory:
            super().__init__(key_data.priv_exp, key_data.modulos)

        elif type(key_data) is str:
            parts = key_data.split("%")
            super().__init__(parts[0], parts[1])

        else: raise TypeError("can't create a key from this")

    def decrypt(self, data):
        cypher_data = self.crypt(int(data, 16))
        return fromInt(cypher_data)

    def sign(self, data):
        hash_value = sha256(data)
        cypher_data = self.crypt(hash_value)
        return hex(cypher_data).replace("0x", "")
