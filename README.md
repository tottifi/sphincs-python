# sphincs-python
This is a non-official SPHINCS+ python implementation created from scratch based on SPHINCS+ algorithm of digital signatures which can be found at https://sphincs.org/.

**DO NOT USE THIS PROGRAM FOR PROFESSIONNAL USE** unless you know what you are doing. This work isn't official and hasn't been approved by anybody, it's main purpose was to understand how SPHINCS+ works and to try how we could use it. This program might have some flaws and is not meant to be fast.

## Program sources
Two folders contains SPHINCS+ algorithm, but only the _package_ folder is recommanded to be used
- The main useful part of this code is located in the _package_ folder, containing classes you can use to work with the algorithm.
- The _src_ folder contain the same functions before they have been transformed into a class. Each Cryptographics methods are split in differents files (_WOTS+_, _XMSS_ and _FORS_).

## Using the Program
A Jupyter Notebook called _Sphincs Example_ is provided to help you learn how to use the program.

Copy the _package_ folder in your project root.
Start by importing the SPHINCS Library:
```
from package.sphincs import Sphincs
```
And create an instance of SPHINCS+:
```
sphincs = Sphincs()
```
You can change SPHINCS+ parameters (_n_, _w_, _w_, _d_, _k_ and _a_) using its provided functions:
```
sphincs.set_winternitz(4)
# Or
sphincs.set_w(4)
```
Generate a key pair: (Return a secret key and a public key)
```
sk, pk = sphincs.generate_key_pair()
```
Signing your message, message must be exprimed as bytes! (Return a signature)
```
m = b'What are quantum mechanics? I don't know. People who repair quantums, I suppose.'
signature = sphincs.sign(m, sk)
```
Verifying a signature: (Return True if signature is correct, False elsewere)
```
sphincs.verify(signature, m, pk)
```

