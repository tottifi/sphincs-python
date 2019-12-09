"""
Hashing functions and pseudo-random generators (tweakables)
"""

from src.parameters import *
from src.adrs import *
import hashlib

def hash(seed, adrs: ADRS, value, digest_size=n):

    m = hashlib.sha256()

    m.update(bytes(seed))
    m.update(adrs.to_bin())
    m.update(bytes(value))

    hashed = m.digest()[:digest_size]

    return hashed