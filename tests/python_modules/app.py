import jwt
import os
import numpy as np
import pandas as pd
import pycurl
from logzero import logger
from Crypto.Cipher import AES


def test_pandas():
    pd.test()
    logger.info("test_pandas passed")

def test_pycrypto():
    key = AES.new('This is a key123', AES.MODE_CBC, 'This is an IV456')
    message = "abcdefghijklmnop"
    ciphertext = key.encrypt(message)
    print(ciphertext)

    cleartext = key.decrypt(ciphertext)
    print(cleartext)
    logger.info("test_pycrypto passed")

def test_pycurl():
    with open('pycurl.html', 'wb') as f:
        c = pycurl.Curl()
        c.setopt(c.URL, 'http://pycurl.io/')
        c.setopt(c.WRITEDATA, f)
        c.perform()
        c.close()
    f = open('pycurl.html', 'r')
    print(f.read(100))
    logger.info("test_pycurl passed")

def test_jwt():
    key = "secret"
    encoded = jwt.encode({"some": "payload"}, key, algorithm="HS256")
    print(encoded)

    clear = jwt.decode(encoded, key, algorithms="HS256")
    print(clear)
    logger.info("test_jwt passed")

def test_numpy():
    np.test()
    logger.info("test_numpy passed")

if __name__ == "__main__":

#    test_numpy()

    test_pandas()

    test_pycrypto()

    test_pycurl()

    test_jwt()
