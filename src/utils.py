"""
Utils functions
"""


def print_bytes_int(value):
    array = []
    for val in value:
        array.append(val)
    print(array)


def print_bytes_bit(value):
    array = []
    for val in value:
        for j in range(7, -1, -1):
            array.append((val >> j) % 2)
    print(array)
