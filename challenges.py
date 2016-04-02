import base64
import collections
import itertools

from Crypto.Cipher import AES


def from_hex(x):
    return bytearray(base64.b16decode(x, True))


def to_hex(x):
    return base64.b16encode(x).lower()


# 1
def hex_to_b64(h):
    return base64.b64encode(base64.b16decode(h, True))


# 2
def xor_hex(a, b):
    return to_hex(bytearray(x ^ y for x, y in zip(from_hex(a), from_hex(b))))


# http://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
FREQUENCY_TABLE_STR = {
    'E': 0.1202,
    'T': 0.0910,
    'A': 0.0812,
    'O': 0.0768,
    'I': 0.0731,
    'N': 0.0695,
    'S': 0.0628,
    'R': 0.0602,
    'H': 0.0592,
    'D': 0.0432,
    'L': 0.0398,
    'U': 0.0288,
    'C': 0.0271,
    'M': 0.0261,
    'F': 0.0230,
    'Y': 0.0211,
    'W': 0.0209,
    'G': 0.0203,
    'P': 0.0182,
    'B': 0.0149,
    'V': 0.0111,
    'K': 0.0069,
    'X': 0.0017,
    'Q': 0.0011,
    'J': 0.0010,
    'Z': 0.0007,
}

FREQUENCY_TABLE = {ord(c): v for c, v in FREQUENCY_TABLE_STR.iteritems()}


def plaintext_score(x):
    """Lower is better.  x is a bytearray."""
    score = 0

    # Letter frequencies: add absolute differences.
    letter_counts = collections.defaultdict(int)
    num_letters = 0
    for b in x:
        if 97 <= b <= 122 or 65 <= b <= 90:
            letter_counts[64 + b % 32] += 1
            num_letters += 1

        if 97 <= b <= 122 or b == 32:  # lowercase + space
            pass
        elif 65 <= b <= 90:  # uppercase
            score += 5
        elif 48 <= b <= 57 or b == 44 or b == 46:  # numbers + period + comma
            score += 50
        elif 9 <= b <= 13 or 32 <= b <= 126:  # string.printable
            score += 300
        else:
            score += 1000000

    for b, freq in FREQUENCY_TABLE.iteritems():
        # TODO: should square these or scale by freq or something?
        score += abs(letter_counts[b] - freq * num_letters)

    return score


# 3
def find_xor(b):
    options = [bytearray(c ^ i for c in b) for i in range(256)]
    options.sort(key=plaintext_score)
    return str(options[0])


# 4
def find_xor_many():
    with open('4.txt') as f:
        strings = map(from_hex, filter(None, f.read().split()))
    options = [bytearray(c ^ i for c in b)
               for i in range(256)
               for b in strings]
    options.sort(key=plaintext_score)
    return str(options[0])


# 5
def repeating_key_xor(plain, key):
    """plain and key are bytearrays, returns a bytearray"""
    return bytearray(
        c ^ k for c, k in itertools.izip(plain, itertools.cycle(key)))


def num_ones(byte):
    ans = 0
    while byte:
        if byte % 2:
            ans += 1
        byte = byte // 2
    return ans


def hamming_distance(a, b):
    return sum(num_ones(i ^ j) for i, j in itertools.izip(a, b))


def keysize_score(b, keysize):
    dists = [
        hamming_distance(b[i * keysize:(i + 1) * keysize],
                         b[(i + 1) * keysize:(i + 2) * keysize])
        for i in xrange(4)]
    return float(sum(dists)) / len(dists) / keysize


# 6
def find_repeating_key_xor(b):
    keysize_distances = [(keysize, keysize_score(b, keysize))
                         for keysize in xrange(2, 41)]
    keysize_distances.sort(key=lambda x: x[1])
    key_options = []
    for keysize, _ in keysize_distances[:4]:
        blocks = [b[i::keysize] for i in xrange(keysize)]
        key_options.append(bytearray())

        for block in blocks:
            options = [(i, plaintext_score(bytearray(c ^ i for c in block)))
                       for i in xrange(256)]
            options.sort(key=lambda x: x[1])
            key_options[-1] += chr(options[0][0])

    options = [(key, repeating_key_xor(b, key)) for key in key_options]
    options.sort(key=lambda x: plaintext_score(x[1]))
    return options[0]


# 7
def aes_decrypt(b, k):
    cipher = AES.new(k, AES.MODE_ECB)
    return bytearray(cipher.decrypt(bytes(b)))


def is_ecb(b):
    assert len(b) % 16 == 0
    blocks = [b[i:i + 16] for i in xrange(0, len(b), 16)]
    return bool(len(blocks) - len(set(map(str, blocks))))


# 8
def aes_detect(bs):
    return [b for b in bs if is_ecb(b)]
