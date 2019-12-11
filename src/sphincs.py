"""
Main SPHINCS+ functions
"""

import math
import hashlib
import random  # Only for Pseudo-randoms
import os  # Secure Randoms

from src.utils import *
from src.parameters import *
from src.tweakables import *
from src.adrs import *
from src.wots import *
from src.xmss import *
from src.hypertree import *
from src.fors import *


# Input: (none)
# Output: SPHINCS+ key pair (SK,PK)
def spx_keygen():
    secret_seed = os.urandom(n)
    secret_prf = os.urandom(n)
    public_seed = os.urandom(n)

    public_root = ht_pk_gen(secret_seed, public_seed)

    return [secret_seed, secret_prf, public_seed, public_root], [public_seed, public_root]


# Input: Message M, private key SK = (SK.seed, SK.prf, PK.seed, PK.root)
# Output: SPHINCS+ signature SIG
def spx_sign(m, secret_key):
    adrs = ADRS()

    secret_seed = secret_key[0]
    secret_prf = secret_key[1]
    public_seed = secret_key[2]
    public_root = secret_key[3]

    opt = bytes(n)
    if RANDOMIZE:
        opt = os.urandom(n)
    r = prf_msg(secret_prf, opt, m)
    sig = [r]

    size_md = math.floor((k * a + 7) / 8)
    size_idx_tree = math.floor((h - h // d + 7) / 8)
    size_idx_leaf = math.floor((h // d + 7) / 8)

    digest = hash_msg(r, public_seed, public_root, m, size_md + size_idx_tree + size_idx_leaf)
    tmp_md = digest[:size_md]
    tmp_idx_tree = digest[size_md:(size_md + size_idx_tree)]
    tmp_idx_leaf = digest[(size_md + size_idx_tree):len(digest)]

    md_int = int.from_bytes(tmp_md, 'big') >> (len(tmp_md) * 8 - k * a)
    md = md_int.to_bytes(math.ceil(k * a / 8), 'big')

    idx_tree = int.from_bytes(tmp_idx_tree, 'big') >> (len(tmp_idx_tree) * 8 - (h - h // d))
    idx_leaf = int.from_bytes(tmp_idx_leaf, 'big') >> (len(tmp_idx_leaf) * 8 - (h // d))

    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)
    adrs.set_type(ADRS.FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)

    sig_fors = fors_sign(md, secret_seed, public_seed, adrs.copy())
    sig += [sig_fors]

    pk_fors = fors_pk_from_sig(sig_fors, md, public_seed, adrs.copy())

    adrs.set_type(ADRS.TREE)
    sig_ht = ht_sign(pk_fors, secret_seed, public_seed, idx_tree, idx_leaf)
    sig += [sig_ht]

    return sig


# Input: Message M, signature SIG, public key PK
# Output: Boolean
def spx_verify(m, sig, public_key):
    adrs = ADRS()
    r = sig[0]
    sig_fors = sig[1]
    sig_ht = sig[2]

    public_seed = public_key[0]
    public_root = public_key[1]

    size_md = math.floor((k * a + 7) / 8)
    size_idx_tree = math.floor((h - h // d + 7) / 8)
    size_idx_leaf = math.floor((h // d + 7) / 8)

    digest = hash_msg(r, public_seed, public_root, m, size_md + size_idx_tree + size_idx_leaf)
    tmp_md = digest[:size_md]
    tmp_idx_tree = digest[size_md:(size_md + size_idx_tree)]
    tmp_idx_leaf = digest[(size_md + size_idx_tree):len(digest)]

    md_int = int.from_bytes(tmp_md, 'big') >> (len(tmp_md) * 8 - k * a)
    md = md_int.to_bytes(math.ceil(k * a / 8), 'big')

    idx_tree = int.from_bytes(tmp_idx_tree, 'big') >> (len(tmp_idx_tree) * 8 - (h - h // d))
    idx_leaf = int.from_bytes(tmp_idx_leaf, 'big') >> (len(tmp_idx_leaf) * 8 - (h // d))

    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)
    adrs.set_type(ADRS.FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)

    pk_fors = fors_pk_from_sig(sig_fors, md, public_seed, adrs)

    adrs.set_type(ADRS.TREE)
    return ht_verify(pk_fors, sig_ht, public_seed, idx_tree, idx_leaf, public_root)
