"""
WOTS+ Functions
"""

from src.parameters import *
from src.tweakables import *

# Input: Input string X, start index i, number of steps s, public seed PK.seed, address ADRS
# Output: value of F iterated s times on X
def chain(X, i, s, public_seed, adrs):
    if s == 0:
        return X

    if (i + s) > (w - 1):
        return -1



