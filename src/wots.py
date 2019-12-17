"""
WOTS+ Functions
"""

from src.parameters import *
from src.tweakables import *
from src.adrs import *
import math


# Input: Input string X, start index i, number of steps s, public seed PK.seed, address ADRS
# Output: value of F iterated s times on X
def chain(x, i, s, public_seed, adrs: ADRS):
    if s == 0:
        return bytes(x)

    if (i + s) > (w - 1):
        return -1

    tmp = chain(x, i, s - 1, public_seed, adrs)

    adrs.set_hash_address(i + s - 1)
    tmp = hash(public_seed, adrs, tmp, n)

    return tmp


# Input: secret seed SK.seed, address ADRS
# Output: WOTS+ private key sk
def wots_sk_gen(secret_seed, adrs: ADRS):  # Not necessary
    sk = []
    for i in range(0, len_0):
        adrs.set_chain_address(i)
        adrs.set_hash_address(0)
        sk.append(prf(secret_seed, adrs.copy()))
    return sk


# Input: secret seed SK.seed, address ADRS, public seed PK.seed
# Output: WOTS+ public key pk
def wots_pk_gen(secret_seed, public_seed, adrs: ADRS):
    wots_pk_adrs = adrs.copy()
    tmp = bytes()
    for i in range(0, len_0):
        adrs.set_chain_address(i)
        adrs.set_hash_address(0)
        sk = prf(secret_seed, adrs.copy())
        tmp += bytes(chain(sk, 0, w - 1, public_seed, adrs.copy()))

    wots_pk_adrs.set_type(ADRS.WOTS_PK)
    wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    pk = hash(public_seed, wots_pk_adrs, tmp)
    return pk


# Input: Message M, secret seed SK.seed, public seed PK.seed, address ADRS
# Output: WOTS+ signature sig
def wots_sign(m, secret_seed, public_seed, adrs):
    csum = 0

    msg = base_w(m, w, len_1)

    for i in range(0, len_1):
        csum += w - 1 - msg[i]

    padding = (len_2 * math.floor(math.log(w, 2))) % 8 if (len_2 * math.floor(math.log(w, 2))) % 8 != 0 else 8
    csum = csum << (8 - padding)
    csumb = csum.to_bytes(math.ceil((len_2 * math.floor(math.log(w, 2))) / 8), byteorder='big')
    csumw = base_w(csumb, w, len_2)
    msg += csumw

    sig = []
    for i in range(0, len_0):
        adrs.set_chain_address(i)
        adrs.set_hash_address(0)
        sk = prf(secret_seed, adrs.copy())
        sig += [chain(sk, 0, msg[i], public_seed, adrs.copy())]

    return sig


def wots_pk_from_sig(sig, m, public_seed, adrs: ADRS):
    csum = 0
    wots_pk_adrs = adrs.copy()

    msg = base_w(m, w, len_1)

    for i in range(0, len_1):
        csum += w - 1 - msg[i]

    padding = (len_2 * math.floor(math.log(w, 2))) % 8 if (len_2 * math.floor(math.log(w, 2))) % 8 != 0 else 8
    csum = csum << (8 - padding)
    csumb = csum.to_bytes(math.ceil((len_2 * math.floor(math.log(w, 2))) / 8), byteorder='big')
    csumw = base_w(csumb, w, len_2)
    msg += csumw

    tmp = bytes()
    for i in range(0, len_0):
        adrs.set_chain_address(i)
        tmp += chain(sig[i], msg[i], w - 1 - msg[i], public_seed, adrs.copy())

    wots_pk_adrs.set_type(ADRS.WOTS_PK)
    wots_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    pk_sig = hash(public_seed, wots_pk_adrs, tmp)
    return pk_sig
