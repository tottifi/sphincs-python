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

pk = fors_pk_gen(secret_seed, public_seed, ADRS())
sig = fors_sign(bytes([254, 61]), secret_seed, public_seed, ADRS())

print(pk)
print(fors_pk_from_sig(sig, bytes([254, 61]), public_seed, ADRS()))

print(4)

"""
pk = xmss_pk_gen(secret_seed, public_seed, ADRS())
sig = xmss_sign(m, secret_seed, idx, public_seed, ADRS())
print(pk)
print(xmss_pk_from_sig(idx, sig, m, public_seed, ADRS()))
"""