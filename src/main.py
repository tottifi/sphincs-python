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

pk = xmss_pk_gen(secret_seed, public_seed, ADRS())
print_bytes_int(pk)

sig_xmss = xmss_sign(m, secret_seed, 1, public_seed, ADRS())

pk_sig = xmss_pk_from_sig(1, sig_xmss, m, public_seed, ADRS())
print_bytes_int(pk_sig)