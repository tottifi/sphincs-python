"""
Parameters
"""

import math

# Randomness to signatures
RANDOMIZE = True

# Security parameter (in bytes)
n = 32

# Winternitz parameter
w = 16

# Hypertree height
h = 12

# Hypertree layers
d = 3

# FORS trees numbers
k = 8

# FORS trees height
a = 4


# SUB VALUES (AUTOMATICS)

# Message Lengt for WOTS
len_1 = math.ceil(8 * n / math.log(w, 2))
len_2 = math.floor(math.log(len_1 * (w - 1), 2) / math.log(w, 2)) + 1
len_0 = len_1 + len_2

# XMSS Sub-Trees height
h_prime = h // d

# FORS trees leaves number
t = 2**a