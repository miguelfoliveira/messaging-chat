
import keys
import os 
key = os.urandom(32)
text = 'foobarnsvnsnvs svdsdv'

ciphertext = keys.encrypt('ECDHE-AES128_OFB-SHA256',key,text)
print ciphertext


