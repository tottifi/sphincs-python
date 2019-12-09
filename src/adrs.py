"""
Class ADRS, stock address from sphincs
"""

class ADRS:

    def __init__(self):
        self.layer = 0
        self.tree_address = 0

        self.type = 0

        # Words for which role can change depending on ADRS.type
        self.word_1 = 0
        self.word_2 = 0
        self.word_3 = 0

    def to_full_value(self):
        full = self.word_3
        full += self.word_2 * 256
        full += self.word_1 * 256**2
        full += self.type * 256**3
        full += self.tree_address * 256**4
        full += self.layer * 256**7

        return full

    def to_bin(self):
        adrs = bytes([
            self.layer,
            self.tree_address // (256**2),
            (self.tree_address % 256**2) // 256,
            self.tree_address % 256,
            self.type,
            self.word_1,
            self.word_2,
            self.word_3
        ])

        return adrs

    def reset_words(self):
        self.word_1 = 0
        self.word_2 = 0
        self.word_3 = 0
