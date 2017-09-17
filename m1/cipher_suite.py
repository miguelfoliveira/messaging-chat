

import random
from Crypto.PublicKey import ElGamal
from Crypto.Util.number import GCD
from Crypto.Hash import SHA


class Cipher:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.master_key = None
        self.cipher_suite = None

    # 'ECDHE-AES128-SHA256'
    def verify_cipher_suite(self, cipher, data):
        ciphers = cipher.split('-')
        print ciphers[0]
        if ciphers[0] == 'ECDHE':
            pass
        elif ciphers[0] == 'ElGamal':
            key = ElGamal.generate(1024, Random.new().read)
            h = SHA.new(data).digest()
            while 1:
                k = random.StrongRandom().randint(1, key.p - 1)
                if GCD(k, key.p - 1) == 1:
                    break
            sig = key.sign(h, k)
            #
            if key.verify(h, sig):
                print "OK"
            else:
                print "Incorrect signature"
        else:
            pass

def main():
    c = Cipher()
    c.verify_cipher_suite('ECDHE-AES128-SHA256')


if __name__ == '__main__':
    main()