
import socket
import sys
import json
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import keys
import base64
import os
import logging
import select
import OpenSSL.crypto as openssl
import PyKCS11

TERMINATOR = "\n\n"
port = 8080
host = "127.0.0.1"
session_connected = False
session_client_connect = False



class mysocket:

    def __init__(self, sock=None):
        if sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            self.sock = sock

    def connect(self, host, port):
        self.sock.connect((host, port))

    def send(self, msg):
        totalsent = 0
        MSGLEN = len(msg)
        while totalsent < MSGLEN:
            sent = self.sock.send(json.dumps(msg)+TERMINATOR)
            if sent == 0:
                raise RuntimeError("socket connection broken")
            totalsent = totalsent + sent


    def receive(self):
       # while True:
        reply = self.sock.recv(20048)
        if not reply:
            print "done"
            return []
        replies = reply.split('\n\n')
        return replies

    def close(self):
        self.sock.close()              

class Connection(object):
    def __init__(self):
		self.id = random.randint(0, 100000)
		self.public_key = None
		self.private_key = None 	# used on connect process
		self.new_private_key = None # used on secure process
		self.master_secret = None
		self.final_master_secret = None
		self.cipher_suite = None
		self.server_public_key = None
		self.rand_client = None
		self.rand_srv = None
		self.sock = mysocket()
		self.sock.connect(host, port)
		self.clients = {}			# list of connected clients
		self.ids = []				# list of client ids
		self.you = -1				# client id
		self.name = None			# client name
		self.pkcs11 = PyKCS11.PyKCS11Lib()
		self.pkcs11.load('libpteidpkcs11.so')
		self.store = keys.loadCerts()
		self.storeServer = keys.loadServerStore()
		self.dst_val = {}  # key = hash, value = msg
		self.part_cons = {}
		self.tmp = {}

    def loop(self):
		# Client Name
		#self.name = raw_input('\nName: ')
		self.name = keys.getCN_CC(self.cert)
		print 'Name:\n',self.name				
		self.connect_send(self.name)
		while True:
			rsocks = select.select([self.sock.sock, sys.stdin],[],[])[0]
			for sock in rsocks:
				if sock == self.sock.sock:
					for m in self.sock.receive():
						self.msg_receive(m)
				elif sock == sys.stdin:
					data = sys.stdin.readline()
					self.command(data)
										
           
    def command(self,command):
		""" Command executed by the client """
		#try:
		command = command[:-1]
		if command == 'msg':
			for m in self.dst_val:
				print "%s - %s"% (m, self.dst_val[m])
			return
		if command == 'help':
			print self.need_help()
			return
		if command == 'list':
			self.list_clients()	
			return
		elif command == 'list-connected':
			if self.clients.keys() == []:
				print 'No clients connected!\n'
				return
			else:
				print '\nClients connected:'
				for c in self.clients.keys():
					print 'Client: ',str(c)
				print '\n'	
				return	
		command_split = command.split('-')
		print '\n'
		if command_split[0] == 'connect':
			if int(command_split[1]) == int(self.you):
				print '\nERROR: You can not communicate with yourself!\n'
				return
			elif int(command_split[1]) not in self.ids:
				print '\nERROR: Client',str(command_split[1]),'not available!\n'
				return
			else:
				self.send_client_connect(command_split[1])
				return
		if command_split[0] == 'disconnect':	
			if str(command_split[1]) not in self.clients:
				print '\nERROR: Client',str(command_split[1]),'not connected!\n'
				return
			else:
				self.delClient(command_split[1])
				self.send_client_disconnect(command_split[1])
				print '\nClient disconnected: ', str(command_split[1])
				return	
		if command_split[0] == 'send':
			if str(command_split[1]) not in self.clients:
				print '\nERROR: Client',str(command_split[1]),'not connected!\n'
				return
			else:
				self.send_client_com(command_split[1], command_split[2])
				return
		else:
			print 'Invalid command!\n'
			print self.need_help()	
			return	
		#except:
		#	print 'Invalid command!\n'
		#	print self.need_help()	
			
#---------------------------------------------------------------------------------------------------------------											
			
    def need_help(self):
		"""Help commands menu"""
		h = '__________________________________________\n'
		h += '\nValid commands:\n'
		h += '__________________________________________\n'
		h += '\nlist: list all available clients\n'
		h += 'connect-[id]: connect to client\n'
		h += 'list-connected: list all connected clients\n'
		h += 'disconnect-[id]: disconnect from client\n'
		h += 'send-[id]: send message to client\n'	
		h += '__________________________________________\n'	
		return h	
		
#---------------------------------------------------------------------------------------------------------------	

    def connect_send(self, name, msg = None):
		""" Process a connect message from server (phase = 1) """
		msg = {'type': 'connect', 'phase': 1, 'name': self.name, 'id': self.id, 'ciphers': ['NONE'], 'data': {}}
		  
		print '-------------------------------------------\nBegin Server-Client Handshake\n-------------------------------------------'
		msg['ciphers'] = ['ECDHE-AES128_CTR-SHA256', 'ECDHE-AES256_CTR-SHA384']

		# Assinatura
		#signature = keys.signClient(self.session, self.obj[0], json.dumps(msg,sort_keys = True))
		#msg['sign'] = base64.b64encode(signature)

		msg['data'] = {'certificate':base64.b64encode(self.cert)}

		Hash = keys.hash(msg)
		self.dst_val[Hash] = msg.copy()


		self.sock.send(msg)

    def msg_receive(self, msg):
		#print '\n\n'
		#print msg
		if 'type' and 'connect' in msg:
			m = json.loads(msg)
			self.connect_receive(m)
		elif 'type' and 'secure' in msg:
			m = json.loads(msg)
			self.secure_receive(m)
		elif 'type' and 'ack' in msg:
			m = json.loads(msg)
			self.receive_ack(m)

    def connect_receive(self, reply=None):
		""" Process a connect message from server (phase > 1)"""
		msg = {'type': 'connect', 'phase': reply['phase']+1, 'name': self.name, 'id': self.id, 'ciphers': ['NONE'], 'data': {}}

		#print "\n\n"
		#print reply

		if reply['phase'] == 2:

			Hash = keys.hash(reply)
			ack = {'type':'ack','hash':Hash}
			self.sock.send(ack)

			self.servercert = base64.b64decode(reply['data']['certificate'])

			#cert verificate
			cert = openssl.load_certificate(openssl.FILETYPE_ASN1, self.servercert)

			if keys.verifycert(cert,self.storeServer,True) == False:
				logging.warning("Invalid Certificate!!")
				return

			self.cipher_suite = reply['ciphers']
			msg['ciphers'] = reply['ciphers']

			self.clientRandom = os.urandom(32)
			self.randomServer = base64.b64decode(reply['data']['challenge'])
			sign_randServer = keys.signClient(self.session, self.obj[0], self.randomServer)

			msg['data'] = {'sign_challenge': base64.b64encode(sign_randServer), 'challenge':base64.b64encode(self.clientRandom)}

		if reply['phase'] == 4:

			Hash = keys.hash(reply)
			ack = {'type':'ack','hash':Hash}
			self.sock.send(ack)

			sign = base64.b64decode(reply['data']['sign_challenge'])
			#validation
			if keys.verifySign(sign, self.servercert,self.clientRandom ) == False:
				logging.warning("Invalid Signature!!")
				return 

			print "\n\n"
			print "Challenge Response Complete!!"
			print "\n\n"

			# keys pair creation
			self.public_key, self.private_key = keys.verify_cipher_suite(self.cipher_suite)
			msg['ciphers'] = reply['ciphers']
			# client random
			self.rand_client = os.urandom(32)

			msg['data'] = {'public_key': self.public_key, 'client_random': base64.b64encode(self.rand_client)}
			
			# assinar toda a msg
			signature = keys.signClient(self.session, self.obj[0], json.dumps(msg,sort_keys = True))
			msg['sign'] = base64.b64encode(signature)

		if reply['phase'] == 6:

			Hash = keys.hash(reply)
			ack = {'type':'ack','hash':Hash}
			sign_ack = keys.signClient(self.session, self.obj[0], json.dumps(ack,sort_keys = True))
			ack['sign'] = base64.b64encode(sign_ack)
			self.sock.send(ack)


			sign = base64.b64decode(reply['sign'])
			del reply['sign']
			#validation

			if keys.verifySign(sign, self.servercert, json.dumps(reply,sort_keys=True)) == False:
				logging.warning("Invalid Signature!!")
				return

			self.server_public_key = keys.deserialize_public_key(base64.b64decode(reply['data']['public_key']))
			self.master_secret = keys.generate_master_secret(self.server_public_key, self.private_key)
			# get random server
			self.rand_srv = base64.b64decode(reply['data']['server_random'])
			self.final_master_secret = keys.generate_final_master_secret(self.master_secret, self.rand_client + self.rand_srv)
			# get server sign

			# Make the secret secure
			session_connected = True
			#
			print '-------------------------------------------\nServer-Client Handshake completed!!\n-------------------------------------------'
			if session_connected:
				print '-------------------------------------------\nBegin Client-Connect!!\n-------------------------------------------'
				# Automatic list of clients list
				self.list_clients()
				print '\n',self.need_help()
				return	

		Hash = keys.hash(msg)
		self.dst_val[Hash] = msg.copy()
		self.sock.send(msg)
		
#---------------------------------------------------------------------------------------------------------------		
			
	#This is a secure message
	# CARALHO
    def secure_send(self, msg_json):
		""" Process a secure message from server """
		# Cipher: new private key + old public key
		msg = {'type': 'secure', 'sa-data':{}, 'payload':{} }
		new_public_key, new_private_key = keys.verify_cipher_suite(self.cipher_suite)
					
		new_master_secret = keys.generate_master_secret(self.server_public_key, new_private_key)		
		tmp_rand_client = os.urandom(32)
		new_final_master_secret = keys.generate_final_master_secret(new_master_secret, self.rand_srv + tmp_rand_client)
		ciphertext , client_iv = keys.encrypt(self.cipher_suite,new_final_master_secret,msg_json)
				
		msg['sa-data'] = {'hash': base64.b64encode(keys.message_authentication(self.cipher_suite, new_final_master_secret, ciphertext)),
			'iv': base64.b64encode(client_iv), 'random':base64.b64encode(tmp_rand_client)}
		msg['payload'] = {'ciphertext': base64.b64encode(ciphertext),'public_key': new_public_key}

		# assinar toda a msg
		signature = keys.signClient(self.session, self.obj[0], json.dumps(msg,sort_keys = True))
		msg['sign'] = base64.b64encode(signature)

		if 'src' in msg_json.keys() and msg_json['type'] != 'ack':
			h = keys.hash(msg_json)
			self.dst_val[h] = msg_json

			#save secure msg
			Hash = keys.hash(msg)
			self.dst_val[Hash] = msg.copy()

			self.sock.send(msg)

			return

		#save secure msg
		Hash = keys.hash(msg)
		self.dst_val[Hash] = msg.copy()

		self.sock.send(msg)
		return
		
    def secure_receive(self, msg_json): 
		""" Process a secure message from server """
		
		# verificar a assinatura antes de fazer o decrypt7
		tmp = msg_json.copy()

		sign = base64.b64decode(msg_json['sign'])
		del msg_json['sign']
		#validation

		if keys.verifySign(sign, self.servercert, json.dumps(msg_json,sort_keys=True)) == False:
			logging.warning("Invalid Signature!!")
			return		

		# CONTINUE
		# CONA
		# Decipher: public key received + old private key
		ciphertext = base64.b64decode(msg_json['payload']['ciphertext'])
		public_key = keys.deserialize_public_key(base64.b64decode(msg_json['payload']['public_key']))
		server_hash = base64.b64decode(msg_json['sa-data']['hash'])
		server_iv = base64.b64decode(msg_json['sa-data']['iv'])
		server_random = base64.b64decode(msg_json['sa-data']['random'])
		new_master_secret = keys.generate_master_secret(public_key, self.private_key)

		new_final_master_secret = keys.generate_final_master_secret(new_master_secret,self.rand_client + server_random)
		client_hash = keys.message_authentication(self.cipher_suite, new_final_master_secret, ciphertext)

		msg_json['payload'] = keys.decrypt(self.cipher_suite,new_final_master_secret,ciphertext,server_iv)

		#print '\nPayloadSecure'
		#print msg_json['payload']
		
		if (server_hash != client_hash):
			logging.warning('Client Hash and Server Hash do not match!')


		if msg_json['payload']['type'] == 'ack':
			self.receive_ack(msg_json['payload'])
			return

		Hash = keys.hash(tmp)
		ack = {'type':'ack','hash':Hash}
		sign_ack = keys.signClient(self.session, self.obj[0], json.dumps(ack,sort_keys = True))
		ack['sign'] = base64.b64encode(sign_ack)
		self.secure_send(ack)
			
		if msg_json['payload']['type'] == 'list':
			self.receive_list_clients(msg_json['payload'], self.id)
			return 

		if msg_json['payload']['type'] == 'client-connect':
			self.receive_client_connect(msg_json['payload'])
			return

		
		if msg_json['payload']['type'] == 'client-disconnect':
			self.receive_client_disconnect(msg_json['payload'])
			return 	

		#print '123456'
		#print msg_json['payload']
		Hash = keys.hash(msg_json['payload'])
		ack = {'type':'ack', 'hash':Hash, 'src': self.id, 'dst': msg_json['payload']['src']}
		sign_ack = keys.signClient(self.session, self.obj[0], json.dumps(ack,sort_keys = True))
		ack['sign'] = base64.b64encode(sign_ack)
		self.secure_send(ack)
		
		
		if msg_json['payload']['type'] == 'client-com':
			self.receive_client_com(msg_json['payload'])
			
#---------------------------------------------------------------------------------------------------------------			
			
				
	# The server will ignore the data field if sent from the client.	
    def list_clients(self):
		""" List the available clients """
		msg = {'type': 'list'}
		self.secure_send(msg)
	
    def receive_list_clients(self, client_list, c_id):
		 """ Deals with the ids list """
		 clients = client_list['data']
		 print '\nClients List: \n'
		 for k in clients:  		 
			 if k['id'] == c_id:
				self.you = k['id']
				print k['name'],': ', k['id'], '[You]'
			 else:
				 print k['name'],': ', k['id']	 
			 if k['id'] not in self.ids: 	 	
				self.ids.append(k['id'])
		 print '\n'		  	 		    		  
		 return self.ids
		 
#---------------------------------------------------------------------------------------------------------------		 
		 
    def addClient(self, c_id):
        """ Adds a client[c_id] """
        if c_id in self.clients:
            logging.error('Client NOT Added: %s already exists', self.clients[c_id])
            return

        newclient = Client(c_id)
        self.clients[c_id] = newclient
        logging.info('Client added: %s', newclient)		
        
    def delClient(self, c_id):
		""" Delete a client[c_id] """
		if c_id not in self.clients:
			logging.error("Client NOT deleted: %s not found", self.clients[c_id])
			return

		client = self.clients[c_id]

		if client.id in self.clients.keys():
			del self.clients[c_id]
			
		logging.info('Client disconnected: ', client)  
		
#---------------------------------------------------------------------------------------------------------------		   
		 
    def send_client_connect(self,dst):
		 """ Process a client-connect message from client (phase = 1) """
		 msg = {'type':'client-connect', 'src': self.id , 'dst': dst, 'phase': 1, 'ciphers': [], 'data': {} }
		 
		 # Client addition for connect
		 self.addClient(dst)
		 # Client added to the clients list
		 client = self.clients[dst]
		 
		 msg['ciphers'] = ['ECDHE-AES128_CTR-SHA256', 'ECDHE-AES256_CTR-SHA384']

		 # send cert
		 msg['data'] = {'certificate':base64.b64encode(self.cert)}

		 # Assinat toda a msg
		 #signature = keys.signClient(self.session, self.obj[0], json.dumps(msg,sort_keys = True))
		 #msg['sign'] = base64.b64encode(signature)

		 # Update
		 client.cipher_suite = msg['ciphers']

		 Hash = keys.hash(msg)
		 self.dst_val[Hash] = msg.copy()

		 self.secure_send(msg)
		 
    def receive_client_connect(self, reply):
		""" Process a client-connect message from client (phase > 1) """
		msg = {'type':'client-connect'}

		if reply['phase'] == 1:

			Hash = keys.hash(reply)
			ack = {'type':'ack','hash':Hash, 'src': self.id, 'dst': reply['src']}
			self.secure_send(ack)

			#get peer_client cert
			cli_cert = base64.b64decode(reply['data']['certificate'])

			#cert verification
			cert = openssl.load_certificate(openssl.FILETYPE_ASN1, cli_cert)

			if keys.verifycert(cert,self.store) == False:
				logging.warning("Invalid Certificate!!")
				return

			self.addClient(str(reply['src']))
			client= self.clients[str(reply['src'])]
			
			if str(reply['src']) not in self.clients:
				logging.warning('Client not supported!')
				
			ciphers = ['ECDHE-RSA-CTR-SHA256', 'ECDHE-AES256_CTR-SHA384','ECDHE-AES128_CTR-SHA256']
			
			# Cipher_suite selection mode
			cipher = [c for c in reply['ciphers'] if c in ciphers]
			
			if cipher == []:
				logging.warning('Does not support cipher spec!')
				return	


			msg['src'] =  reply['dst']	
			msg['dst'] =  reply['src']
			msg['phase'] = reply['phase']+1
			msg['ciphers'] = cipher[0]

			# Update
			client.cipher_suite = msg['ciphers']
			client.cert = cli_cert

			client.randomCH = os.urandom(32)

			msg['data'] = {'certificate': base64.b64encode(self.cert),'challenge':base64.b64encode(client.randomCH)}

			Hash = keys.hash(msg)
			self.dst_val[Hash] = msg.copy()

			self.secure_send(msg)
			return

		if reply['phase'] == 2:

			Hash = keys.hash(reply)
			ack = {'type':'ack','hash':Hash, 'src': self.id, 'dst': reply['src']}
			self.secure_send(ack)


			#get peer_client cert
			cli_cert = base64.b64decode(reply['data']['certificate'])

			#cert verification
			cert = openssl.load_certificate(openssl.FILETYPE_ASN1,cli_cert)

			if keys.verifycert(cert,self.store) == False:
				logging.warning("Invalid Certificate!!")
				return

			client = self.clients[str(reply['src'])]
			
			if reply['ciphers'] not in client.cipher_suite:
				logging.warning('Does not support cipher spec!')
				return
				
			# Update
			client.cipher_suite = reply['ciphers']
			client.cert = cli_cert

			peerRandom = base64.b64decode(reply['data']['challenge'])
			client.randomCH = os.urandom(32)

			sign_peerRandom = keys.signClient(self.session, self.obj[0], peerRandom)

			msg['dst'] =  reply['src']
			msg['src'] =  reply['dst']
			msg['phase'] = reply['phase'] +1
			msg['ciphers'] = reply['ciphers']

			msg['data'] = {'sign_challenge':base64.b64encode(sign_peerRandom),'challenge':base64.b64encode(client.randomCH)}

			Hash = keys.hash(msg)
			self.dst_val[Hash] = msg.copy()

			self.secure_send(msg)
			return


		if reply['phase'] == 3:

			Hash = keys.hash(reply)
			ack = {'type':'ack','hash':Hash, 'src': self.id, 'dst': reply['src']}
			self.secure_send(ack)

			client = self.clients[str(reply['src'])]

			# get client sign
			sign = base64.b64decode(reply['data']['sign_challenge'])

			#validation
			if keys.verifySign(sign, client.cert, client.randomCH)== False:
				logging.warning("Invalid Signature!!")
				return



			peerRandom = base64.b64decode(reply['data']['challenge'])

			sign_peerRandom = keys.signClient(self.session, self.obj[0], peerRandom)

			msg['data'] = {'sign_challenge':base64.b64encode(sign_peerRandom)}


			client.cipher_suite = reply['ciphers']

			msg['dst'] =  reply['src']
			msg['src'] =  reply['dst']
			msg['phase'] = reply['phase'] +1


			Hash = keys.hash(msg)
			self.dst_val[Hash] = msg.copy()

			self.secure_send(msg)
			return

		if reply['phase'] == 4:

			Hash = keys.hash(reply)
			ack = {'type':'ack','hash':Hash, 'src': self.id, 'dst': reply['src']}
			self.secure_send(ack)

			client = self.clients[str(reply['src'])]

			# get client sign
			sign = base64.b64decode(reply['data']['sign_challenge'])

			#validation
			if keys.verifySign(sign, client.cert, client.randomCH) == False:
				logging.warning("Invalid Signature!!")
				return

			print "\n\n"
			print "Challenge Response Complete!!"
			print "\n\n"

			client.public_key, client.private_key = keys.verify_cipher_suite(client.cipher_suite)
			client.random = os.urandom(32)
			msg['data'] = {'public_key': client.public_key, 'random': base64.b64encode(client.random)}

			msg['dst'] =  reply['src']
			msg['src'] =  reply['dst']
			msg['phase'] = reply['phase']+1
			#msg['ciphers'] = reply['ciphers']


			# Assinar toda a mensagem
			signature = keys.signClient(self.session, self.obj[0], json.dumps(msg,sort_keys = True))
			msg['sign'] = base64.b64encode(signature)

			Hash = keys.hash(msg)
			self.dst_val[Hash] = msg.copy()

			self.secure_send(msg)
			return

		if reply['phase'] == 5:

			Hash = keys.hash(reply)
			ack = {'type':'ack','hash':Hash, 'src': self.id, 'dst': reply['src']}
			sign_ack = keys.signClient(self.session, self.obj[0], json.dumps(ack,sort_keys = True))
			ack['sign'] = base64.b64encode(sign_ack)
			self.secure_send(ack)

			client = self.clients[str(reply['src'])]


			# get client sign
			sign = base64.b64decode(reply['sign'])
			del reply['sign']

			#validation
			if keys.verifySign(sign, client.cert, json.dumps(reply,sort_keys=True)) == False:
				logging.warning("Invalid Signature!!")
				return

			# CONTINUE

			#client.cipher_suite = reply['ciphers']



			client.public_key, client.private_key = keys.verify_cipher_suite(client.cipher_suite)

			client.random = os.urandom(32)
			client.received_public_key = keys.deserialize_public_key(base64.b64decode(reply['data']['public_key']))
			client.received_random = base64.b64decode(reply['data']['random'])
			client.client_client_master_secret = keys.generate_master_secret(client.received_public_key,client.private_key)
			client.client_client_final_master = keys.generate_final_master_secret(client.client_client_master_secret,client.received_random+client.random)

			msg['data'] = {'public_key': client.public_key, 'random':base64.b64encode(client.random)}
			msg['dst'] =  reply['src']
			msg['src'] =  reply['dst']
			msg['phase'] = reply['phase'] +1

			# enviar info do Hardware
			info_hash = keys.participantConsistency_Hash()
			info = keys.participantConsistency()

			# cifrar info do Hardware
			tmp  = { 'hash': info_hash, 'info':info}
			encrypt_info, iv  = keys.encrypt(client.cipher_suite, client.client_client_final_master, tmp )

			msg['encrypt_hardware'] ={ 'encrypt_info':base64.b64encode(encrypt_info) , 'iv': base64.b64encode(iv)}


			# Assinar toda a mensagem
			signature = keys.signClient(self.session, self.obj[0], json.dumps(msg,sort_keys = True))
			msg['sign'] = base64.b64encode(signature)


			Hash = keys.hash(msg)
			self.dst_val[Hash] = msg.copy()

			self.secure_send(msg)
			return

		if reply['phase'] == 6:

			Hash = keys.hash(reply)
			ack = {'type':'ack','hash':Hash, 'src': self.id, 'dst': reply['src']}
			sign_ack = keys.signClient(self.session, self.obj[0], json.dumps(ack,sort_keys = True))
			ack['sign'] = base64.b64encode(sign_ack)
			self.secure_send(ack)

			client = self.clients[str(reply['src'])]

			# get client sign
			sign = base64.b64decode(reply['sign'])
			del reply['sign']

			#validation
			if keys.verifySign(sign, client.cert, json.dumps(reply,sort_keys=True)) == False:
				logging.warning("Invalid Signature!!")
				return

			# CONTINUE

			client.received_public_key = keys.deserialize_public_key(base64.b64decode(reply['data']['public_key']))
			client.client_client_master_secret = keys.generate_master_secret(client.received_public_key,client.private_key )
			client.received_random = base64.b64decode(reply['data']['random'])
			client.client_client_final_master = keys.generate_final_master_secret(client.client_client_master_secret,client.random+client.received_random )


			to_decrypt = base64.b64decode(reply['encrypt_hardware']['encrypt_info'])
			iv_todecrypt =  base64.b64decode(reply['encrypt_hardware']['iv'])

			cleartext = keys.decrypt(client.cipher_suite , client.client_client_final_master, to_decrypt ,iv_todecrypt)

			if client.cert in self.part_cons.keys():
				if self.part_cons[client.cert] != (cleartext['hash'][1], cleartext['info'][1]):
					print 'Hard novo!'
					print '\n Mac Adrress'+ str(cleartext['info']['brand'])

			# Update
			self.part_cons[client.cert] = (cleartext['hash'][1], cleartext['info'][1])

			print 'Connection to the Client finished with sucess!\n'
			return



#-------------------------------------------------------------------------------------------------------

#---------------------------------------------------------------------------------------------------------------
	#CARALHO
    def send_client_com(self,dst,cleartext):
		""" Process a client-com message from client """
		msg = {'type':'client-com', 'src': self.id,'dst': dst, 'data': {}}
		# Client in session
		client = self.clients[str(dst)]
		 
		# Cipher: new private key + old public key
		new_public_key, new_private_key = keys.verify_cipher_suite(client.cipher_suite)
		client.client_client_master_secret = keys.generate_master_secret(client.received_public_key, new_private_key)
		tmp_random = os.urandom(32)
		client.client_client_final_master = keys.generate_final_master_secret(client.client_client_master_secret,client.received_random + tmp_random)
		 
		ciphertext ,iv = keys.encrypt(client.cipher_suite,client.client_client_final_master ,cleartext)
		client.digest = keys.message_authentication(client.cipher_suite, client.client_client_final_master, ciphertext)
		
		 
		msg['data'] = {'hash':base64.b64encode(client.digest),
					   'iv' : base64.b64encode(iv),
					   'public_key': new_public_key,
					   'ciphertext': base64.b64encode(ciphertext),
					   'random': base64.b64encode(tmp_random)
					   }

		# Assinar toda a mensagem
		signature = keys.signClient(self.session, self.obj[0], json.dumps(msg,sort_keys = True))
		msg['sign'] = base64.b64encode(signature)

		Hash = keys.hash(msg)
		self.dst_val[Hash] = msg.copy()

		self.secure_send(msg)
		
		
    def receive_client_com(self,reply):
		""" Process a client-com message from client """

		# Client in session
		client = self.clients[str(reply['src'])]

		# get client sign
		sign = base64.b64decode(reply['sign'])
		del reply['sign']

		#validation
		if keys.verifySign(sign, client.cert, json.dumps(reply,sort_keys=True)) == False:
			logging.warning("Invalid Signature!!")
			return

		# CONTINUE
		# CONA
		# Decipher: public key received + old private key
		ciphertext = base64.b64decode(reply['data']['ciphertext'])
		tmp_public_key = keys.deserialize_public_key(base64.b64decode(reply['data']['public_key']))
		digest = base64.b64decode(reply['data']['hash'])
		tmp_received_random = base64.b64decode(reply['data']['random'])
		iv = base64.b64decode(reply['data']['iv'])
		
		client.client_client_master_secret = keys.generate_master_secret(tmp_public_key, client.private_key)
		client.client_client_final_master = keys.generate_final_master_secret(client.client_client_master_secret, client.random + tmp_received_random)
		client.digest = keys.message_authentication(client.cipher_suite,client.client_client_final_master, ciphertext)
		
		if client.digest != digest:
			 logging.warning('Client Hash and Server Hash do not match!')
		
		cleartext = keys.decrypt(client.cipher_suite, client.client_client_final_master, ciphertext, iv)
		 
		print '__________________________________________\n'
		print 'Client:',str(reply['src']),'# ',cleartext
		print '__________________________________________\n'
		
		#if cleartext != '':
			#self.send_client_ack(reply['src'])
        	
#---------------------------------------------------------------------------------------------------------------		
    
    def send_client_disconnect(self, dest):
		""" Process a client-disconnect message from aclient """
		msg = {'type': 'client-disconnect', 'src': self.id, 'dst': dest, 'data': {}}
		# Assinar toda a mensagem
		signature = keys.signClient(self.session, self.obj[0], json.dumps(msg,sort_keys = True))
		msg['sign'] = base64.b64encode(signature)

		Hash = keys.hash(msg)
		self.dst_val[Hash] = msg.copy()

		self.secure_send(msg)		
			
				
    def receive_client_disconnect(self, reply):
		""" Process a client-disconnect message from calient (last phase) """

		# get client sign
		sign = base64.b64decode(reply['sign'])
		del reply['sign']

		#validation
		if keys.verifySign(sign, self.cert, json.dumps(reply,sort_keys=True)) == False:
			logging.warning("Invalid Signature!!")
			return

		self.delClient(str(reply['src']))
		print 'Client ', str(reply['src']) , ' disconnected!!'
		return		
			
#---------------------------------------------------------------------------------------------------------------	

    def send_client_ack(self,dst):
		 """ Process a ack message from a client """
		 msg = {'type': 'ack', 'src':self.id, 'dst': dst, 'data': None}
		 self.secure_send(msg)
		 
    def receive_ack(self,reply):
		""" Process a ack message from a client (last phase) """

		if 'src' in reply.keys() and 'dst' in reply.keys():
			# TODO CHECK SIGNATURE
			
			if 'sign' in reply.keys():
				#print '\n1111112333'
				#print self.clients

				# Client in session
				client = self.clients[str(reply['src'])]


				# get client sign
				sign = base64.b64decode(reply['sign'])
				del reply['sign']

				#validation
				if keys.verifySign(sign, client.cert, json.dumps(reply,sort_keys=True)) == False:
					logging.warning("Invalid Signature!!")
					return

			try:
				del self.dst_val[reply['hash']]
			except:
				print "ack for Unknown message"

			print '\nClient', str(reply['src']), 'received your message with sucess!\n'
		else:

			if 'sign' in reply.keys():
				#print '\n1111112333'


				# get client sign
				sign = base64.b64decode(reply['sign'])
				del reply['sign']

				#validation
				if keys.verifySign(sign, self.servercert, json.dumps(reply,sort_keys=True)) == False:
					logging.warning("Invalid Signature!!")
					return			
			try:
				del self.dst_val[reply['hash']]
			except:
				print "ack for Unknown message"

		

		
#---------------------------------------------------------------------------------------------------------------
    def loginCC(self):
		slot = raw_input("Slot:")
		self.slot = self.pkcs11.getSlotList()[int(slot)]
		self.session = self.pkcs11.openSession(self.slot)
		print "PIN:"
		pin = raw_input()
		self.session.login(pin)
		self.obj = self.session.findObjects()
		self.cert = self.session.getAttributeValue(self.obj[1],[PyKCS11.CKA["CKA_VALUE"]],True)[0]
		self.cert = ''.join(chr(i) for i in self.cert)
		#debug
		with open('certificado.der', 'wb') as fout:
			fout.write(self.cert)
			fout.close()
			print 'Certificado escrito no ficheiro certificado.der!'
		#print keys.getAttributesCC(self.cert)


				
class Client(object):
	def __init__(self, c_id):
		self.id = c_id
		self.dst = None
		self.name = "Unknown"
		self.cipher_suite = None
		self.received_public_key = None
		self.public_key = None
		self.private_key = None
		self.new_private_key = None
		self.new_public_key = None
		self.random = None
		self.digest = None
		self.received_random = None
		self.client_client_master_secret = None
		self.client_client_final_master = None
		self.cert = None
		
def main():
	sock = mysocket()
	con = Connection()
	con.loginCC()
	con.loop()
	sock.close()

if __name__ == '__main__':
    main()
