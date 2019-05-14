import os
import hashlib
import itertools
import time

import flask

BLOCK_SIZE = 64
KEY = os.urandom(BLOCK_SIZE)
OPAD = '\x5c' * BLOCK_SIZE
IPAD = '\x36' * BLOCK_SIZE


def xor_bytes(a, b):
    return ''.join(
        map(chr, [ord(x) ^ ord(y) for x, y in itertools.izip(a, b)]))


def hmac(msg):
    return hashlib.sha1(
        xor_bytes(KEY, OPAD) + hashlib.sha1(
            xor_bytes(KEY, IPAD) + msg).digest()).hexdigest()


def insecure_compare(a, b):
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:
            return False
        time.sleep(0.05)
    return True


app = flask.Flask(__name__)


@app.route('/test')
def test():
    if not insecure_compare(hmac(str(flask.request.args['file'])),
                            str(flask.request.args['signature'])):
        flask.abort(403)
    return 'OK'


@app.route('/sign')
def sign():
    return hmac(str(flask.request.args['file']))
