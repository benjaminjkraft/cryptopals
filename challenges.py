import base64
import collections
import itertools
import os
import random
import urlparse
import urllib

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
    return to_hex(xor_bytearrays(from_hex(a), from_hex(b)))


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
    return xor_bytearrays(plain, itertools.cycle(key))


def num_ones(byte):
    ans = 0
    while byte:
        if byte % 2:
            ans += 1
        byte = byte // 2
    return ans


def hamming_distance(a, b):
    return sum(map(num_ones, xor_bytearrays(a, b)))


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
def aes_ecb_decrypt(b, k):
    cipher = AES.new(bytes(k), AES.MODE_ECB)
    return bytearray(cipher.decrypt(bytes(b)))


def aes_ecb_encrypt(b, k):
    b = pkcs7_pad(b)
    cipher = AES.new(bytes(k), AES.MODE_ECB)
    return bytearray(cipher.encrypt(bytes(b)))


def is_ecb(b):
    assert len(b) % 16 == 0
    blocks = [b[i:i + 16] for i in xrange(0, len(b), 16)]
    return bool(len(blocks) - len(set(map(str, blocks))))


# 8
def aes_detect(bs):
    return [b for b in bs if is_ecb(b)]


# 9
def pkcs7_pad(bs, block_length=16):
    assert block_length < 256
    bytes_to_pad = -len(bs) % block_length
    if bytes_to_pad == 0:
        bytes_to_pad = block_length
    return bs + chr(bytes_to_pad) * bytes_to_pad


def xor_bytearrays(a, b):
    return bytearray(x ^ y for x, y in itertools.izip(a, b))


# 10
def aes_cbc_decrypt(b, k, iv):
    assert len(b) % 16 == 0
    last_ct = iv
    pt = bytearray()
    for i in xrange(0, len(b), 16):
        this_ct = b[i:i + 16]
        pt += xor_bytearrays(aes_ecb_decrypt(this_ct, k), last_ct)
        last_ct = this_ct
    return pt


def aes_cbc_encrypt(b, k, iv):
    b = pkcs7_pad(b)
    last_ct = iv
    ct = bytearray()
    for i in xrange(0, len(b), 16):
        this_pt = b[i:i + 16]
        last_ct = aes_ecb_encrypt(xor_bytearrays(this_pt, last_ct), k)
        ct += last_ct
    return ct


def rand_aes_key():
    return os.urandom(16)


def encrypt_either_ecb_cbc(b):
    k = rand_aes_key()
    iv = bytearray(rand_aes_key())
    b = pkcs7_pad(bytearray(os.urandom(random.randrange(5, 11))) + b +
                  bytearray(os.urandom(random.randrange(5, 11))))
    if random.randrange(2) == 0:
        return ("ecb", aes_ecb_encrypt(b, k))
    else:
        return ("cbc", aes_cbc_encrypt(b, k, iv))


# 11
def detect_ecb_cbc(encrypt_fn):
    pt = bytearray('x' * 64)
    mode, ct = encrypt_fn(pt)
    if ct[16:32] == ct[32:48]:
        our_mode = 'ecb'
    else:
        our_mode = 'cbc'
    if mode == our_mode:
        return True
    else:
        print mode, pt, ct
        return False


KEY_12 = rand_aes_key()
APPEND_12 = bytearray(base64.b64decode("""
    Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK
    """))


def encrypt_ecb_12(b):
    pt = pkcs7_pad(b + APPEND_12)
    return aes_ecb_encrypt(pt, KEY_12)


# 12
def decrypt_ecb(encrypt_fn):
    # Detect block size
    last_value = encrypt_fn('')
    for i in itertools.count(1):
        this_value = encrypt_fn('A' * i)
        if this_value[:8] == last_value[:8]:
            break
        else:
            last_value = this_value
    block_size = i - 1
    assert block_size == 16, block_size

    # Detect ECB
    pt = bytearray('A' * (4 * block_size))
    ct = encrypt_fn(pt)
    assert ct[block_size:2 * block_size] == ct[2 * block_size:3 * block_size]

    # Length-extension attack
    pt = bytearray('')
    for j in itertools.count():  # index of block to work on
        for i in xrange(block_size):  # index of byte to work on (from end)
            bytes_to_check = block_size * (j + 1)
            padding = bytearray('A' * (block_size - 1 - i))
            possible_cts = {
                bytes(encrypt_fn(padding + pt + c)[:bytes_to_check]): c
                for c in map(chr, xrange(256))
            }
            try:
                next_char = possible_cts[
                    bytes(encrypt_fn(padding)[:bytes_to_check])]
            except:
                # If we don't find it, that means we finished the end of the
                # ciphertext, and also picked up a byte of padding; remove it
                # and return.
                return pt[:-1]
            pt += next_char


def urldecode(s):
    return {k: v[0] for k, v in urlparse.parse_qs(s).items()}


def profile_for(email):
    return ("email=%s&uid=10&role=user" %
            email.replace('=', '%3D').replace('&', '%26'))


KEY_13 = rand_aes_key()


def encrypt_profile_for(email):
    return aes_ecb_encrypt(profile_for(email), KEY_13)


def pkcs_unpad(b):
    num_bytes = b[-1]
    if len(set(b[-num_bytes:])) == 1:
        return b[:-num_bytes]
    else:
        raise ValueError("incorrect padding on %s" % base64.b64encode(b))


def decrypt_profile(prof):
    return urldecode(bytes(pkcs_unpad(aes_ecb_decrypt(prof, KEY_13))))


# 13
def admin_profile():
    # pad email= to put admin in a new block, then pad admin to fill a block.
    encrypted_admin = encrypt_profile_for(
        '\x0a' * 10 + 'admin' + '\x0b' * 11 + '@example.com')[16:32]
    # 'email=&uid=10&role=' is 19 chars; we want to fill a block, so we use
    # 'x@example.com' to fill out 32, and then grab only the first 2 blocks to
    # truncate the "user".
    encrypted_prof = encrypt_profile_for('x@example.com')[:32]
    return encrypted_prof + encrypted_admin
