"""
Hashing functions and pseudo-random generators (tweakables)
"""

from src.utils import *
from src.parameters import *
from src.adrs import *
import math
import hashlib
import random


def hash(seed, adrs: ADRS, value, digest_size=n):
    m = hashlib.sha256()

    m.update(seed)
    m.update(adrs.to_bin())
    m.update(value)

    hashed = m.digest()[:digest_size]

    return hashed


def prf(secret_seed, adrs):
    random.seed(int.from_bytes(secret_seed + adrs.to_bin(), "big"))
    return random.randint(0, 256 ** n).to_bytes(n, byteorder='big')


def hash_msg(r, public_seed, public_root, value, digest_size=n):
    m = hashlib.sha256()

    m.update(r)
    m.update(public_seed)
    m.update(public_root)
    m.update(value)

    hashed = m.digest()[:digest_size]

    i = 0
    while len(hashed) < digest_size:
        i += 1
        m = hashlib.sha256()

        m.update(r)
        m.update(public_seed)
        m.update(public_root)
        m.update(value)
        m.update(bytes([i]))

        hashed += m.digest()[:digest_size - len(hashed)]

    return hashed


def prf_msg(secret_seed, opt, m):
    random.seed(int.from_bytes(secret_seed + opt + hash_msg(b'0', b'0', b'0', m, n*2), "big"))
    return random.randint(0, 256 ** n).to_bytes(n, byteorder='big')


# Input: len_X-byte string X, int w, output length out_len
# Output: out_len int array basew
def base_w(x, w, out_len):
    vin = 0
    vout = 0
    total = 0
    bits = 0
    basew = []

    for consumed in range(0, out_len):
        if bits == 0:
            total = x[vin]
            vin += 1
            bits += 8
        bits -= math.floor(math.log(w, 2))
        basew.append((total >> bits) % w)
        vout += 1

    return basew


def sig_wots_from_sig_xmss(sig):
    return sig[0:len_0]


def auth_from_sig_xmss(sig):
    return sig[len_0:]


def sigs_xmss_from_sig_ht(sig):
    sigs = []
    for i in range(0, d):
        sigs.append(sig[i*(h_prime + len_0):(i+1)*(h_prime + len_0)])

    return sigs


def auths_from_sig_fors(sig):
    sigs = []
    for i in range(0, k):
        sigs.append([])
        sigs[i].append(sig[(a+1) * i])
        sigs[i].append(sig[((a+1) * i + 1):((a+1) * (i+1))])

    return sigs
