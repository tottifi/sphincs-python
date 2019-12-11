"""
FORS Function
"""

from src.parameters import *
from src.tweakables import *
from src.adrs import *

# Input: secret seed SK.seed, address ADRS, secret key index idx = it+j
# Output: FORS private key sk
def fors_sk_gen(secret_seed, adrs: ADRS, idx):
    adrs.set_tree_height(0)
    adrs.set_tree_index(idx)
    sk = prf(secret_seed, adrs.copy())

    return sk


# Input: Secret seed SK.seed, start index s, target node height z, public seed PK.seed, address ADRS
# Output: n-byte root node - top node on Stack
def fors_treehash(secret_seed, s, z, public_seed, adrs):
    if s % (1 << z) != 0:
        return -1

    stack = []

    for i in range(0, 2**z):
        adrs.set_tree_height(0)
        adrs.set_tree_index(s + i)
        sk = prf(secret_seed, adrs.copy())
        node = hash(public_seed, adrs.copy(), sk, n)

        adrs.set_tree_height(1)
        adrs.set_tree_index(s + i)
        if len(stack) > 0:
            while stack[len(stack) - 1]['height'] == adrs.get_tree_height():
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node = hash(public_seed, adrs.copy(), stack.pop()['node'] + node, n)

                adrs.set_tree_height(adrs.get_tree_height() + 1)

                if len(stack) <= 0:
                    break
        stack.append({'node': node, 'height': adrs.get_tree_height()})

    return stack.pop()['node']


# Input: Secret seed SK.seed, public seed PK.seed, address ADRS
# Output: FORS public key PK
def fors_pk_gen(secret_seed, public_seed, adrs: ADRS):
    fors_pk_adrs = adrs.copy()

    root = bytes()
    for i in range(0, k):
        root += fors_treehash(secret_seed, i * t, a, public_seed, adrs)

    fors_pk_adrs.set_type(ADRS.FORS_ROOTS)
    fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    pk = hash(public_seed, fors_pk_adrs, root)
    return pk


# Input: Bit string M, secret seed SK.seed, address ADRS, public seed PK.seed
# Output: FORS signature SIG_FORS
def fors_sign(m, secret_seed, public_seed, adrs):
    m_int = int.from_bytes(m, 'big')
    sig_fors = []

    for i in range(0, k):
        idx = (m_int >> (k - 1 - i) * a) % t

        adrs.set_tree_height(0)
        adrs.set_tree_index(i * t + idx)
        sig_fors += [prf(secret_seed, adrs.copy())]

        auth = []

        for j in range(0, a):
            s = math.floor(idx // 2 ** j)
            if s % 2 == 1:  # XORING idx/ 2**j with 1
                s -= 1
            else:
                s += 1

            auth += [fors_treehash(secret_seed, i * t + s * 2**j, j, public_seed, adrs.copy())]

        sig_fors += auth

    return sig_fors


# Input: FORS signature SIG_FORS, (k lg t)-bit string M, public seed PK.seed, address ADRS
# Output: FORS public key
def fors_pk_from_sig(sig_fors, m, public_seed, adrs: ADRS):
    m_int = int.from_bytes(m, 'big')

    sigs = auths_from_sig_fors(sig_fors)
    root = bytes()

    for i in range(0, k):
        idx = (m_int >> (k - 1 - i) * a) % t

        sk = sigs[i][0]
        adrs.set_tree_height(0)
        adrs.set_tree_index(i * t + idx)
        node_0 = hash(public_seed, adrs.copy(), sk)
        node_1 = 0

        auth = sigs[i][1]
        adrs.set_tree_index(i * t + idx)  # Really Useful?

        for j in range(0, a):
            adrs.set_tree_height(j+1)

            if math.floor(idx / 2**j) % 2 == 0:
                adrs.set_tree_index(adrs.get_tree_index() // 2)
                node_1 = hash(public_seed, adrs.copy(), node_0 + auth[j], n)
            else:
                adrs.set_tree_index((adrs.get_tree_index() - 1) // 2)
                node_1 = hash(public_seed, adrs.copy(), auth[j] + node_0, n)

            node_0 = node_1

        root += node_0

    fors_pk_adrs = adrs.copy()
    fors_pk_adrs.set_type(ADRS.FORS_ROOTS)
    fors_pk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    pk = hash(public_seed, fors_pk_adrs, root, n)
    return pk

