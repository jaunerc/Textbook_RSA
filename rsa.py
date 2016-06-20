import random


def mod(a, n):
    """
    Calculates a modulo n. This method returns only positive numbers or zero.
    :param a: Integer number.
    :param n: Integer number.
    :return: a mod n
    """
    r = a % n
    if r < 0:
        r += a
    return r


def str_to_int(s):
    """
    Converts the given string to a integer representation.
    :param s: The string to convert.
    :return: The converted integer.
    """
    h = s.encode('hex')
    return int(h, 16)


def int_to_str(i):
    """
    Converts the given integer to a string representation.
    :param i: The integer to convert.
    :return: The converted string.
    """
    h = '%x' % i
    return h.decode('hex')


"""
GCD Calculation

For a, b elements of Z, the gcd(a, b) is the biggest
integer number, that divides a and b.

Properties of gcd(a, b):
- gcd(a, 0) = abs(a)
- gcd(+-a, +-b) = gcd(a, b)
- gcd(a, b) = gcd(b, a mod b)
"""


def gcd(a, b, it):
    """
    Calculates the gcd of a and b. This function
    uses an euclid algorithm.
    :param a: Integer number.
    :param b: Integer number.
    :param it: Whether this function invokes the iterative or recursive euclid.
    :return: The gcd of a and b.
    """
    a = abs(a)
    b = abs(b)
    if a == 0:
        return b
    if b == 0:
        return a
    elif it:
        return euclid_it(a, b)
    else:
        return euclid_rec(a, b)


def euclid_it(a, b):
    """
    Iterative euclid function.
    :param a: Integer
    :param b: Integer
    :return: The gcd of a and b
    """
    while b != 0:
        if a > b:
            a -= b
        else:
            b -= a
    return a


def euclid_rec(a, b):
    """
    Recursive euclid function.
    :param a: Integer
    :param b: Integer
    :return: The gcd of a and b
    """
    if b != 0:
        return euclid_rec(b, a % b)
    else:
        return a

"""
RSA
"""


class rsaKey:
    """
    This class represents a rsa key. A RSA key stores two values, the modulus
    and the key number.
    """
    def __init__(self, modulus, key):
        """
        Creates a new rsaKey object.
        :param modulus: The modulus number.
        :param key: The key number.
        """
        self.modulus = modulus
        self.key = key


class rsaKeyPair:
    """
    This class represents an RSA key pair.
    """
    def __init__(self, public_key, private_key):
        """
        Creates a new rsaKeyPair object.
        :param public_key: Reference to the public key.
        :param private_key: Reference to the public key.
        """
        self.public_key = public_key
        self.private_key = private_key


def mrt(n, k=10):
    """
    Miller-Rabin-Test to prove, if a number n is probably prime
    or definitely composite.
    see "https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Primality_Testing" for the original
    implementation.
    :param n: integer number to check
    :param k: number of test rounds (= 10 per default)
    :return: True (probably prime) or False (definitely composite)
    """
    if n % 2 == 0:  # False if n is an even number
        return False
    elif n < 5:  # return result for low numbers
        return [False, False, True, True, False][n]

    s, d = 0, n-1
    while d & 1 == 0:  # find s, d so that n - 1 = 2^s * d
        s, d = s + 1, d >> 1 # binary right shift

    bases = set()
    while len(bases) < min(k, n - 4):  # find bases randomly to check n
        r = random.randint(2, n - 2)
        if not (r in bases):
            bases.add(r)

    for a in bases:  # check n for all test bases
        x = pow(a, d, n)  # x = (a^d) mod n
        if x != 1 and x != (n-1):
            for r in range(0, s - 1):
                x = pow(x, 2, n)
                if x == 1:
                    return False
                elif x == n - 1:
                    a = 0
                    break
            if a:
                return False
    return True


def get_random_number(size):
    """
    Returns a random odd number with the bit length of size. This method
    sets the first two and the last bit true. That's because the bit length
    of a product n1 * n2 should be len(n1) + len(n2) (n1,n2 = get_random_number()).
    :param size: The length in bits of the random number.
    :return: A random number.
    """
    if size < 3: # return results for sizes < 3
        return [0, 1, 3, 7][size]

    bits = '11'
    for i in range(1, size-2):
        bits += str(random.getrandbits(1))
    bits += '1'
    return int(bits, 2)


def get_probable_prim(size, k=10):
    """
    Returns a randomly generated number that is probably prime.
    :param size: The length in bits of the number.
    :param k: The number of test rounds (= 10 per default)
    :return: A probable prime number.
    """
    l = get_random_number(size)
    while not (mrt(l, k)):
        l += 2 # try the next odd number
    return l


def extended_euclid(a, b):
    """
    Calculates the gcd and the mod inverse numbers of a and b.
    :param a: element of Integers
    :param b: element of Integers
    :return: gcd, a^-1, b^-1
    """
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return b, x0, y0


def gen_key_pair(size=256):
    """
    Generates a new rsa key pair and returns it.
    :param size: The key size in bits
    :return: RSA key pair
    """
    p, q = get_probable_prim(size/2), get_probable_prim(size/2)

    while p == q:  # choose a new number for q if it is equals with p
        q = get_probable_prim(size/2)

    n = p*q
    phi = (p-1)*(q-1)  # calculates the number of coprimes
    e = 65537  # choose the public key
    d = (extended_euclid(phi, e))[2]  # calculates the private key

    if d < 0:  # workaround for negative mod inverse numbers
        d %= phi

    public_key = rsaKey(n, e)  # creates a public key object
    private_key = rsaKey(n, d)  # creates a private key object
    pair = rsaKeyPair(public_key, private_key)  # creates a key pair object
    return pair


def rsa_enc(rsa_key, data):
    """
    Encrypts the given data with the given key.
    :param rsa_key: Reference to a rsa key.
    :param data: Number to encrypt.
    :return: The encoded number.
    """
    return pow(data, rsa_key.key, rsa_key.modulus)


def rsa_dec(rsa_key, secret):
    """
    Decrypts the given secret with the given key.
    :param rsa_key: Reference to a rsa key.
    :param secret: Number to decrypt.
    :return: The decrypted number.
    """
    return pow(secret, rsa_key.key, rsa_key.modulus)