
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
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as padd
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64
import os
import random
import json
import urllib2
import OpenSSL.crypto as openssl
import PyKCS11
import logging
import asn1crypto
from ocspbuilder import OCSPRequestBuilder
from oscrypto import asymmetric as oscrypto
import platform
import netifaces
import cpuinfo

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
	print plaintext
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

#----------------------------------- m2 -----------------------------------	

def loadCerts():
	store = openssl.X509Store()
	store.set_flags(openssl.X509StoreFlags.X509_STRICT | openssl.X509StoreFlags.POLICY_CHECK)
	for filename in os.listdir('CCCerts'):
		 f = open('CCCerts/' + filename, 'rb')
		 #conteudo
		 fbytes = f.read()
		 #fazer OCSP
		 try:
		 	cert = openssl.load_certificate(openssl.FILETYPE_ASN1, fbytes)
		 except:
		 	cert = openssl.load_certificate(openssl.FILETYPE_PEM, fbytes)
		 # Verificar cert antes de colocar na store
		 store.add_cert(cert)
	return store

def verifycert(certificate,store,server=False):
	# Load do cert ja feito
	# DO OCSP para ver as crl
	if server == False:
		cert = oscrypto.load_certificate(openssl.dump_certificate(openssl.FILETYPE_ASN1, certificate))
		issuer_cert = oscrypto.load_certificate(getIssuer(certificate))
		ocsp_builder = OCSPRequestBuilder(cert, issuer_cert)

		ocsp_request = ocsp_builder.build().dump()

		CN = certificate.get_subject().commonName

		if CN in ('Baltimore CyberTrust Root', 'ECRaizEstado'):
			url = 'http://ocsp.omniroot.com/baltimoreroot/'
		elif CN[:-4] == 'Cartao de Cidadao':
			url = 'http://ocsp.ecee.gov.pt/'
		elif CN[:-5] == 'EC de Autenticacao do Cartao de Cidadao':
			url = 'http://ocsp.root.cartaodecidadao.pt/publico/ocsp'
		else:
			url = 'http://ocsp.auc.cartaodecidadao.pt/publico/ocsp'

		http_req = urllib2.Request(
			url,
			data=ocsp_request,
			headers={'Content-Type': 'application/ocsp-request'}
		)

		http = urllib2.urlopen(http_req)
		ocsp_response = http.read()

		ocsp_response = asn1crypto.ocsp.OCSPResponse.load(ocsp_response)
		response_data = ocsp_response.basic_ocsp_response['tbs_response_data']
		cert_response = response_data['responses'][0]

		#print cert_response['cert_status'].name

		if cert_response['cert_status'].name != 'good':
			return False

	try:
		certV = openssl.X509StoreContext(store, certificate)
		certV.verify_certificate()
	except:
		return False
	return True

# com chave do CC
def signClient(session,key,data):
	return ''.join( chr(i) for i in session.sign(key,data, mecha=PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS,"")) )

# com chave do server -> cryptogrhaphy
def signServer(serverPrivKey, message):
	return serverPrivKey.sign(message,padd.PKCS1v15(),hashes.SHA1())
	

def verifySign(sign,cert,data):
	try:
		certificate = x509.load_der_x509_certificate(cert,default_backend())
		certificate.public_key().verify(sign, data, padd.PKCS1v15(), hashes.SHA1())
	except InvalidSignature:
		return False
	return True

def loadServerKey():
	key = ""
	with open('ServerKeys/Server.pem','rb') as f:
		#conteudo
		fbytes = f.read()
		key = load_pem_private_key(fbytes, password=None, backend=default_backend())
	return key

# Usar no cliente
def loadServerStore():
	store = openssl.X509Store()
	store.set_flags(openssl.X509StoreFlags.X509_STRICT | openssl.X509StoreFlags.POLICY_CHECK)
	with open ('ServerCerts/Root.crt','rb') as f:
		 #conteudo
		 fbytes = f.read()
		 #fazer OCSP

		 cert = openssl.load_certificate(openssl.FILETYPE_PEM, fbytes)
		 store.add_cert(cert)
	return store

def serverCert():
	cert = ""
	with open('ServerCerts/Server.cer','rb') as f:
		 cert = f.read()
	return cert

def controlCert(msg):
	err = False
	if 'error' in msg:
		logging.error(" Certificado Invalido ,impossivel iniciar sessao.")
		err = True
	return err

def controlSign(msg):
	err = False
	if 'error' in msg:
		logging.error(" Assinatura Invalida! Terminar sessao.")
		err = True
	return err

def getCN_CC(cert):
	cert = openssl.load_certificate(openssl.FILETYPE_ASN1,cert)
	nome = cert.get_subject().CN
	return nome

def getNBI(cert):
	cert = openssl.load_certificate(openssl.FILETYPE_ASN1,cert)
	return cert.get_subject().serialNumber

# usado para o destination validation
def hash(msg):
	dumps = json.dumps(msg, sort_keys=True)
	digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
	digest.update(dumps)	
	return base64.b64encode(digest.finalize())

def getIssuer(cert):
	iss = cert.get_issuer()
	for filename in os.listdir('CCCerts'):
		 f = open('CCCerts/' + filename, 'rb')
		 #conteudo
		 fbytes = f.read()
		 try:
		 	cert = openssl.load_certificate(openssl.FILETYPE_ASN1, fbytes)
		 except:
		 	cert = openssl.load_certificate(openssl.FILETYPE_PEM, fbytes)

		 if iss == cert.get_subject():
		 	return openssl.dump_certificate(openssl.FILETYPE_ASN1,cert)

def participantConsistency_Hash():

	info = cpuinfo.get_cpu_info()
	del info['hz_actual_raw']
	del info['hz_advertised_raw']
	SO = platform.platform()
	lista = netifaces.interfaces()
	mac_addr = netifaces.ifaddresses(lista[1])[netifaces.AF_LINK]
	s = str(info) + str(SO) + str(mac_addr)

	return hash(s)

def participantConsistency():

	info = cpuinfo.get_cpu_info()
	del info['hz_actual_raw']
	del info['hz_advertised_raw']
	SO = platform.platform()
	lista = netifaces.interfaces()
	mac_addr = netifaces.ifaddresses(lista[1])[netifaces.AF_LINK]
	s = str(info) + str(SO) + str(mac_addr)

	return s

















	
		

	
			
			
