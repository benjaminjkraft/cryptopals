import base64
import collections
import itertools
import os
import random
import struct
import time
import urlparse

from Crypto.Cipher import AES
import sha1
import tqdm


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
def aes_block_decrypt(b, k):
    cipher = AES.new(bytes(k), AES.MODE_ECB)
    return bytearray(cipher.decrypt(bytes(b)))


aes_ecb_decrypt = aes_block_decrypt


def aes_ecb_encrypt(b, k):
    b = pkcs7_pad(b)
    return aes_block_encrypt(b, k)

def aes_block_encrypt(b, k):
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
        pt += xor_bytearrays(aes_block_decrypt(this_ct, k), last_ct)
        last_ct = this_ct
    return pt


def aes_cbc_encrypt(b, k, iv):
    b = pkcs7_pad(b)
    last_ct = iv
    ct = bytearray()
    for i in xrange(0, len(b), 16):
        this_pt = b[i:i + 16]
        last_ct = aes_block_encrypt(xor_bytearrays(this_pt, last_ct), k)
        ct += last_ct
    return ct


def rand_aes_key(size=16):
    return os.urandom(size)


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


def detect_block_size(encrypt_fn):
    last_value = encrypt_fn('')
    for i in itertools.count(1):
        this_value = encrypt_fn('A' * i)
        if this_value[:8] == last_value[:8]:
            break
        else:
            last_value = this_value
    return i - 1


def detect_cipher(encrypt_fn, block_size):
    pt = bytearray('A' * (4 * block_size))
    ct = encrypt_fn(pt)
    if ct[block_size:2 * block_size] == ct[2 * block_size:3 * block_size]:
        return 'ecb'
    else:
        raise NotImplementedError



# 12
def decrypt_ecb(encrypt_fn):
    block_size = detect_block_size(encrypt_fn)
    assert block_size == 16, block_size

    assert detect_cipher(encrypt_fn, block_size) == 'ecb'

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


# 15
def pkcs7_unpad(b):
    num_bytes = b[-1]
    if len(set(b[-num_bytes:])) == 1:
        return b[:-num_bytes]
    else:
        raise ValueError("incorrect padding on %s" % base64.b64encode(b))


def decrypt_profile(prof):
    return urldecode(bytes(pkcs7_unpad(aes_ecb_decrypt(prof, KEY_13))))


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


KEY_14 = rand_aes_key()


def encrypt_ecb_14(b):
    # Always pad at least one block.
    prefix = bytearray(os.urandom(random.randrange(16, 256)))
    pt = prefix + b + APPEND_12
    return aes_ecb_encrypt(pt, KEY_14)


def gcf(a, b):
    if a == 0:
        return b
    if b == 0:
        return a
    if a < b:
        b, a = a, b
    return gcf(b, a % b)


def detect_prefixed_block_size(encrypt_fn):
    max_block = len(encrypt_fn(''))
    for i in xrange(256):
        max_block = gcf(max_block, len(encrypt_fn('A' * i)))
    return max_block


def detect_prefixed_cipher(encrypt_fn, block_size):
    # check for ECB: any two blocks of an encrypted repeating message are the
    # same.
    if find_dupe_blocks(encrypt_fn('A' * (256 * block_size)), block_size):
        return 'ecb'
    raise NotImplementedError


def find_dupe_blocks(ciphertext, block_size):
    assert len(ciphertext) % block_size == 0
    seen = collections.defaultdict(set)
    for i in xrange(len(ciphertext) // block_size):
        block = bytes(ciphertext[i * block_size:(i + 1) * block_size])
        seen[block].add(i)
    return [sorted(v) for _, v in seen.iteritems() if len(v) > 1]


# 14
def decrypt_prefixed_ecb(encrypt_fn):
    block_size = detect_prefixed_block_size(encrypt_fn)
    assert block_size == 16, block_size

    assert detect_prefixed_cipher(encrypt_fn, block_size) == 'ecb'

    plaintext = bytearray('')
    base_padding = bytearray('A' * block_size)
    sentinel_text = bytearray(
        'B' * block_size + 'C' * 2 * block_size + 'B' * block_size)
    for block in itertools.count():
        for char in xrange(block_size):
            test_text = sentinel_text[:]
            for test_byte in xrange(256):
                test_text.extend((base_padding + plaintext)[(-block_size+1):])
                test_text.append(test_byte)
            test_text.extend(sentinel_text)
            test_text.extend(base_padding[:block_size - 1 - char])
            for i in xrange(block_size * 8):
                dupes = find_dupe_blocks(encrypt_fn(test_text), block_size)
                # We expect to see 4 copies of aes(BBBB), 4 of aes(CCCC), and 2
                # of aes(AAAx)
                dupes.sort(key=lambda x: x[0])
                dupes.sort(key=len)
                if map(len, dupes) != [2, 4, 4]:
                    continue

                a_blocks, b_blocks, c_blocks = dupes
                # double-check we have the expected structure:
                # BBBB CCCC CCCC BBBB AAAx AAAy AAAz BBBB CCCC CCCC BBBB AAA
                first_b = b_blocks[0]
                assert b_blocks == [first_b,
                                    3 + first_b,
                                    256 + 4 + first_b,
                                    256 + 7 + first_b], dupes
                assert c_blocks == [1 + first_b,
                                    2 + first_b,
                                    256 + 5 + first_b,
                                    256 + 6 + first_b], dupes
                first_a, second_a = a_blocks
                assert 3 + first_b < first_a < 256 + 4 + first_b, dupes
                assert second_a == 256 + 7 + first_b, dupes

                next_byte = first_a - first_b - 4
                plaintext.append(next_byte)
                print repr(plaintext)
                break

            else:
                return pkcs7_unpad(plaintext)


KEY_16 = rand_aes_key()
PREFIX_16 = "comment1=cooking%20MCs;userdata="
SUFFIX_16 = ";comment2=%20like%20a%20pound%20of%20bacon"

def encrypt_cbc_16(b):
    b = bytes(b).replace(';', '%3B').replace('=', '%3D')
    nonce = bytearray(rand_aes_key())
    pt = bytearray(PREFIX_16 + b + SUFFIX_16)
    return aes_cbc_encrypt(pt, KEY_16, nonce), nonce


def decrypt_cbc_16(b, nonce):
    pt = aes_cbc_decrypt(b, KEY_16, nonce)
    return ';admin=true;' in pt


# 16
def make_admin_user(encrypt_fn):
    # drop the nonce
    block_size = detect_prefixed_block_size(lambda b: encrypt_fn(b)[0])
    assert block_size == 16, block_size

    # we'll just assume we're in CBC mode
    padding_len = block_size - (len(PREFIX_16) % block_size)  # 16
    padding = 'x' * padding_len
    total_prefix = (padding_len + len(PREFIX_16))
    ct = padding + '\x3aadmin\x3ctrue'
    ct, nonce = encrypt_fn(ct)
    bytes_to_fix = [total_prefix - block_size, total_prefix - block_size + 6]
    for byte in bytes_to_fix:
        ct[byte] ^= 1
    return ct, nonce


KEY_17 = rand_aes_key()

def encrypt_cbc_17():
    with open('17.txt') as f:
        pt = bytearray(base64.b64decode(random.choice(f.read().split())))
    nonce = bytearray(rand_aes_key())
    return aes_cbc_encrypt(pt, KEY_17, nonce), nonce


def decrypt_cbc_17(ct, nonce):
    pt = aes_cbc_decrypt(ct, KEY_17, nonce)
    try:
        pkcs7_unpad(pt)
        return True
    except ValueError:
        return False


# 17
def cbc_oracle_attack(ct, nonce, decrypt_fn):
    block_size = 16

    pt = bytearray()
    for block_i in xrange(len(ct) // block_size):
        block = bytearray()
        for i in xrange(block_size):
            valid_bytes = set()
            for test_byte in xrange(256):
                if block_i == 0:
                    test_ct = ct[:]
                elif (block_i + 1) * block_size < len(ct):
                    test_ct = ct[:-block_i * block_size]
                else:
                    test_ct = nonce + ct[:block_size]
                if i == 0:
                    test_ct[-block_size - 1] ^= test_byte
                    first = decrypt_fn(test_ct, nonce)
                    test_ct[-block_size - 2] ^= 1
                    second = decrypt_fn(test_ct, nonce)
                    if first and second:
                        valid_bytes.add(test_byte)
                else:
                    for j in xrange(i):
                        test_ct[- block_size - j - 1] ^= block[- j - 1] ^ (i + 1)
                    test_ct[- block_size - i - 1] ^= test_byte
                    if decrypt_fn(test_ct, nonce):
                        valid_bytes.add(test_byte)
            assert len(valid_bytes) == 1, (i, valid_bytes)
            block.insert(0, valid_bytes.pop() ^ (i + 1))
        pt = block + pt
    return pt


def run_all_cbc_oracle_attacks():
    plains = set()
    while len(plains) < 10:
        ct, nonce = encrypt_cbc_17()
        plain = cbc_oracle_attack(ct, nonce, decrypt_cbc_17)
        plains.add(bytes(pkcs7_unpad(plain)))
    return '\n'.join([x[6:] for x in sorted(plains)])


def aes_ctr_keystream(k, iv):
    """A generators of ints, which is mostly close enough to a bytearray."""
    for i in itertools.count():
        for c in aes_block_encrypt(iv + struct.pack('<Q', i), k):
            yield c

# 18
def aes_ctr_encrypt(ct, k, iv):
    return xor_bytearrays(ct, aes_ctr_keystream(k, iv))


def encrypted_texts_19():
    k = rand_aes_key()
    with open('19.txt') as f:
        texts = [bytearray(base64.b64decode(line)) for line in f]
    return [aes_ctr_encrypt(text, k, bytearray(8)) for text in texts]

# 19
# texts = encrypted_texts_19()
# [(i, xor_bytearrays(xor_bytearrays(texts[37] + 'aaaaaaaaaaaaaaaaaaaaaaa', text), bytearray("He, too, has been changed in his turn, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))) for i, text in enumerate(texts)]


def encrypted_texts_20():
    k = rand_aes_key()
    with open('20.txt') as f:
        texts = [bytearray(base64.b64decode(line)) for line in f]
    return [aes_ctr_encrypt(text, k, bytearray(8)) for text in texts]


def xor_byte(b, byte):
    return xor_bytearrays(b, itertools.repeat(byte))


# 20
def decrypt_repeated_otp(cts):
    keystream = bytearray()
    for aligned_chars in zip(*cts):
        likely_key_bytes = sorted(
            xrange(256),
            key=lambda byte: plaintext_score(xor_byte(aligned_chars, byte)))
        keystream.append(likely_key_bytes[0])
    return [xor_bytearrays(keystream, ct) for ct in cts]


def int32(n):
    return n & 0xffffffff


# 21
class MT19937(object):
    w = 32
    w_mask = 0xffffffff
    n = 624
    m = 397
    r = 31
    lower_mask = (1 << r) - 1  # 0x7fffffff
    upper_mask = w_mask & ~lower_mask  # 0x80000000
    a = 0x9908b0df
    u, d = 11, 0xffffffff
    s, b = 7, 0x9d2c5680
    t, c = 15, 0xefc60000
    l = 18
    f = 0x6c078965

    def __init__(self, seed=0):
        self._state = [None] * self.n
        self._set_seed(seed)

    def _set_seed(self, seed):
        self._index = self.n
        self._state[0] = seed
        for i in xrange(1, self.n):
            seed = self.w_mask & (self.f * (seed ^ (seed >> (self.w - 2))) + i)
            self._state[i] = seed

    def set_state(self, state):
        self._state = state[:]
        self._index = 0

    def _twist(self):
        for i in xrange(self.n):
            x = (self._state[i] & self.upper_mask) + (
                self._state[(i+1) % self.n] & self.lower_mask)
            y = x >> 1
            if x % 2:
                y = y ^ self.a
            self._state[i] = self._state[(i+self.m) % self.n] ^ y
        self._index = 0

    def __iter__(self):
        return self

    def next(self):
        if self._index == self.n:
            self._twist()

        y = self._state[self._index]
        self._index += 1
        return self.temper(y)

    @classmethod
    def temper(cls, y):
        y = y ^ ((y >> cls.u) & cls.d)
        y = y ^ ((y << cls.s) & cls.b)
        y = y ^ ((y << cls.t) & cls.c)
        y = y ^ (y >> cls.l)
        return cls.w_mask & y


def wait_rng_wait():
    time.sleep(random.randrange(40, 1000))
    rng = MT19937(seed=int(time.time()))
    time.sleep(random.randrange(40, 1000))
    return next(rng)


# 22
def crack_seed(val):
    now = int(time.time())
    for i in xrange(now - 2000, now):
        rng = MT19937(seed=i)
        if val == next(rng):
            return i
    raise RuntimeError("Seed not found")


def untemper(y):
    # Each time, we undo the transform y' = y ^ ((y >> x1) & x2)
    # by recursively computing y = y' ^ ((y >> x1) & x2).
    # We recurse until adding a layer of recursion no longer affects any bits,
    # i.e. for 32/x1 iterations.

    # We don't need to iterate because (y >> l) >> l == 0
    y = y ^ (y >> MT19937.l)

    # we don't need to iterate because ((y << t) & c) << t == 0
    y = y ^ (int32(y << MT19937.t) & MT19937.c)

    y_orig = y
    for _ in xrange(MT19937.w // MT19937.s):
        y = y_orig ^ (int32(y << MT19937.s) & MT19937.b)

    y_orig = y
    for _ in xrange(MT19937.w // MT19937.u):
        y = y_orig ^ ((y >> MT19937.u) & MT19937.d)

    return y



# 23
def clone_mt(vals):
    assert len(vals) == MT19937.n, vals
    
    state = []
    for val in vals:
        assert MT19937.temper(untemper(val)) == val, val
        state.append(untemper(val))

    clone = MT19937()
    clone.set_state(state)
    # Check that we were correct
    clone_vals = list(itertools.islice(clone, MT19937.n))
    assert clone_vals == vals, zip(clone_vals, vals)
    # reset the state again.
    clone.set_state(state)
    # Now replay those same values, double-checking as we go.
    for val in vals:
        assert clone.next() == val
    return clone


def test_clone_mt(seed=238479283):
    mt = MT19937(seed)
    mt2 = clone_mt(list(itertools.islice(mt, mt.n)))
    for a, b in itertools.islice(itertools.izip(mt, mt2), mt.n * 10):
        assert a == b


def ints_to_bytes(iterable):
    for i in iterable:
        for byte in xrange(4):
            yield (i >> (8 * byte)) & 0xff


def mt_keystream(seed):
    return ints_to_bytes(MT19937(seed))


# 24
def mt_encrypt(seed, plain):
    return xor_bytearrays(bytearray(plain), mt_keystream(seed))


def test_mt_encryption():
    plain = os.urandom(random.randrange(64)) + 'A' * 14
    k = random.randrange(65536)
    cipher = mt_encrypt(k, plain)
    assert plain == mt_encrypt(k, cipher)


def decrypt_mt_encryption():
    plain = os.urandom(random.randrange(64)) + 'A' * 14
    k = random.randrange(65536)
    cipher = mt_encrypt(k, plain)
    for test_k in tqdm.tqdm(xrange(65536)):
        if mt_encrypt(test_k, cipher)[-14:] == bytearray('A' * 14):
            assert test_k == k
            return k
    assert False


def make_token():
    k = int(time.time())
    return base64.b64encode(bytearray(itertools.islice(mt_keystream(k), 40)))


def check_token(token):
    fuzz = 100
    t = int(time.time())
    ct = base64.b64decode(token)
    for test_k in xrange(t - fuzz, t + fuzz):
        if bytearray(itertools.islice(mt_keystream(test_k), len(ct))) == ct:
            return True
    return False


# 25
KEY_25 = rand_aes_key()
IV_25 = os.urandom(8)


def get_plain_25():
    with open('25.txt') as f:
        return aes_ecb_decrypt(bytearray(base64.b64decode(f.read())),
                               "YELLOW SUBMARINE")


def edit(ciphertext, offset, newtext):
    plaintext = aes_ctr_encrypt(ciphertext, KEY_25, IV_25)
    plaintext[offset:offset + len(newtext)] = newtext
    return aes_ctr_encrypt(plaintext, KEY_25, IV_25)


def crack_random_access_ctr(plaintext):
    ciphertext = aes_ctr_encrypt(plaintext, KEY_25, IV_25)
    newtext = bytearray('\x00' * len(ciphertext))
    new_plaintext = xor_bytearrays(edit(ciphertext, 0, newtext),
                                   ciphertext)
    print new_plaintext
    assert new_plaintext == plaintext


# 26
KEY_26 = rand_aes_key()
PREFIX_26 = "comment1=cooking%20MCs;userdata="
SUFFIX_26 = ";comment2=%20like%20a%20pound%20of%20bacon"


def encrypt_ctr_26(b):
    b = bytes(b).replace(';', '%3B').replace('=', '%3D')
    iv = os.urandom(8)
    pt = bytearray(PREFIX_26 + b + SUFFIX_26)
    return aes_ctr_encrypt(pt, KEY_26, iv), iv


def decrypt_ctr_26(b, iv):
    pt = aes_ctr_encrypt(b, KEY_26, iv)
    return ';admin=true;' in pt


def make_admin_user_ctr(encrypt_fn):
    # we'll just assume we're in CTR mode
    text = '\x3aadmin\x3ctrue'
    ct, iv = encrypt_fn(text)
    bytes_to_fix = [len(PREFIX_26), len(PREFIX_26) + 6]
    for byte in bytes_to_fix:
        ct[byte] ^= 1
    return ct, iv


# 27
KEY_27 = rand_aes_key()
PREFIX_27 = "comment1=cooking%20MCs;userdata="
SUFFIX_27 = ";comment2=%20like%20a%20pound%20of%20bacon"


def encrypt_cbc_27(b):
    b = bytes(b).replace(';', '%3B').replace('=', '%3D')
    pt = bytearray(PREFIX_27 + b + SUFFIX_27)
    return aes_cbc_encrypt(pt, KEY_27, bytearray(KEY_27))


def decrypt_cbc_27(b):
    pt = aes_cbc_decrypt(b, KEY_27, bytearray(KEY_27))
    if all(i < 128 for i in pt):
        return ';admin=true;' in pt
    else:
        raise ValueError(pt)


def find_key_27():
    pt = 'a' * 48   # at least 3 blocks
    ct = encrypt_cbc_27(pt)
    ct[16:32] = '\x00' * 16
    ct[32:48] = ct[:16]
    try:
        decrypt_cbc_27(ct)
        raise RuntimeError("That should have failed.")
    except ValueError as e:
        return xor_bytearrays(bytearray(e.message[:16]),
                              bytearray(e.message[32:48])) == KEY_27


# 28
def sha1_keyed_mac(message, key):
    return sha1.sha1(key + message)


def check_sha1_keyed_mac(message, key, mac):
    return sha1_keyed_mac(message, key) == mac


# 29
def compute_padding(message_byte_length):
    # cribbed from sha1._produce_digest
    padding = b'\x80'
    padding += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)
    message_bit_length = message_byte_length * 8
    padding += struct.pack(b'>Q', message_bit_length)
    return padding


def extend_sha1(old_digest, old_byte_length, extension):
    registers = tuple(int(old_digest[i:i + 8], 16)
                      for i in xrange(0, len(old_digest), 8))
    padding = compute_padding(old_byte_length)
    hasher = sha1.Sha1Hash()
    hasher._h = registers
    hasher._message_byte_length = old_byte_length + len(padding)
    hasher.update(extension)
    return (padding + extension, hasher.hexdigest())


MESSAGE_29 = ("comment1=cooking%20MCs;userdata=foo;"
              "comment2=%20like%20a%20pound%20of%20bacon")
_KEY_29 = None


def get_key_29():
    global _KEY_29
    if _KEY_29 is None:
        with open('/usr/share/dict/words') as f:
            _KEY_29 = random.choice(f.readlines()).strip()
    return _KEY_29


def make_cookie():
    return MESSAGE_29, sha1_keyed_mac(MESSAGE_29, get_key_29())


def find_sha1_extension(msg, mac):
    for i in xrange(30):
        try:
            full_ext, new_mac = extend_sha1(mac, i + len(msg), ';admin=true')
            if check_sha1_keyed_mac(msg + full_ext, get_key_29(), new_mac):
                return msg + full_ext, new_mac
        except Exception:
            pass
