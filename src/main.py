"""
Main
"""

import math
import hashlib
import random

from src.utils import *
from src.parameters import *
from src.tweakables import *
from src.adrs import *
from src.wots import *
from src.xmss import *
from src.hypertree import *
from src.fors import *

secret_seed = b'42qq'
public_seed = b'420e'

m = b'joff'
idx = 255

pk = ht_pk_gen(secret_seed, public_seed)
sig = ht_sign(m, secret_seed, public_seed, idx, 25)



print(ht_verify(m,sig,public_seed,idx,25,pk))
"""
pk = xmss_pk_gen(secret_seed, public_seed, ADRS())
sig = xmss_sign(m, secret_seed, idx, public_seed, ADRS())
print(pk)
print(xmss_pk_from_sig(idx, sig, m, public_seed, ADRS()))
"""