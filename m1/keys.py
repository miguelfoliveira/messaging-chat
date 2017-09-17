
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac
import base64
import os
import random
import json

def serialize_public_key(public_key):
		return public_key.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo)    
		
def deserialize_public_key(serialized_key):
	key = serialization.load_pem_public_key(serialized_key,backend=default_backend())
	return key
	
def generate_master_secret(public_key, private_key):
	shared_key = private_key.exchange(ec.ECDH(), public_key)   
	return shared_key 

def generate_final_master_secret(master_secret, rand_client_server):
	backend = default_backend()
	info = "hkdf-example"
	hkdf = HKDF(
		algorithm=hashes.SHA256(),
		length=32,
		salt=rand_client_server,
		info=info,
		backend=backend) 
	key = hkdf.derive(master_secret)	
	return key

def verify_cipher_suite(cipher):
	ciphers = cipher.split('-')
	if ciphers[0] == 'ECDHE':
		private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
		public_key = private_key.public_key()
		serialized_public = base64.b64encode(serialize_public_key(public_key))
		return serialized_public, private_key

# Falta ex Padding
def verify_encrypt(cipher_type, key, iv=None):
	backend = default_backend()
	# Verifica se o mesmo iv esta a ser chamado no processo encrypt/decrypt
	if iv == None:
		iv = os.urandom(16) 
		
	ciphers = cipher_type.split('-')
	block_size = 16	
	if ciphers[1] == 'AES128_OFB':
		block_size = 16
		mode = modes.OFB(iv)
	elif ciphers[1] == 'AES128_CTR':
		block_size = 16
		mode = modes.CTR(iv)
	else:
		print 'Encryption cipher type not implemented!!'
	cipher = Cipher(algorithms.AES(key), mode, backend)
	
	return cipher,iv,block_size

def encrypt(cipher_type,key,plaintext):
	msg = json.dumps(plaintext)
	cipher,iv,block_size = verify_encrypt(cipher_type,key)
	encryptor = cipher.encryptor()
	ciphertext = encryptor.update(msg) + encryptor.finalize()
	return ciphertext, iv
	
def decrypt(cipher_type,key,encrypted_text,iv):
	cipher,iv,block_size = verify_encrypt(cipher_type,key,iv)
	decryptor = cipher.decryptor()
	plaintext = decryptor.update(encrypted_text) + decryptor.finalize()
	return json.loads(plaintext)
			
		
def verify_hash(cipher_type):
	result = ''
	ciphers = cipher_type.split('-')
	if ciphers[2] == 'SHA256':
		result = hashes.SHA256()
	elif ciphers[2] == 'SHA384':
		result = hashes.SHA384()
	else:
		print 'Hash type not implemented!!'	
	return result

#	
#	Hash-based message authentication codes (or HMACs) are a tool 
#	for calculating message authentication codes using a cryptographic 
#	hash function coupled with a secret key. You can use an HMAC to verify both the integrity 
#	and authenticity of a message.
def message_authentication(cipher,key,msg):
	hash_type = verify_hash(cipher)
	h = hmac.HMAC(key, hash_type, backend=default_backend())
	h.update(msg)
	final_hash = h.finalize()
	return final_hash
	
	
		

	
			
			
