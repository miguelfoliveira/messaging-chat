
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
        reply = self.sock.recv(2048)
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

    def loop(self):
		# Client Name
		self.name = raw_input('\nName: ')				
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
		try:
			command = command[:-1]
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
		except:
			print 'Invalid command!\n'
			print self.need_help()	
			
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
				
		self.sock.send(msg)

    def msg_receive(self, msg):
        #print msg
        if 'type' and 'connect' in msg:
            m = json.loads(msg)
            self.connect_receive(m)
        elif 'type' and 'secure' in msg:
			 m = json.loads(msg)
			 self.secure_receive(m)

    def connect_receive(self, reply=None):
		""" Process a connect message from server (phase > 1)"""
		msg = {'type': 'connect', 'phase': reply['phase']+1, 'name': self.name, 'id': self.id, 'ciphers': ['NONE'], 'data': {}}
		if reply['phase'] == 2:
			self.cipher_suite = reply['ciphers'] 
			# keys pair creation
			self.public_key, self.private_key = keys.verify_cipher_suite(self.cipher_suite)
			msg['ciphers'] = reply['ciphers']
			# client random
			self.rand_client = os.urandom(32)
			msg['data'] = {'public_key': self.public_key, 'client_random': base64.b64encode(self.rand_client)}
				
		if reply['phase'] == 4:
			self.server_public_key = keys.deserialize_public_key(base64.b64decode(reply['data']['public_key']))
			self.master_secret = keys.generate_master_secret(self.server_public_key, self.private_key)
			# get random server
			self.rand_srv = base64.b64decode(reply['data']['server_random'])
			self.final_master_secret = keys.generate_final_master_secret(self.master_secret, self.rand_client + self.rand_srv)
			# Make the secret secure
			self.rand_client = None
			session_connected = True
			#
			print '-------------------------------------------\nServer-Client Handshake completed!!\n-------------------------------------------'
			if session_connected:
				print '-------------------------------------------\nBegin Client-Connect!!\n-------------------------------------------'
				# Automatic list of clients list
				self.list_clients()
				print '\n',self.need_help()
				return	
						
		self.sock.send(msg)
		
#---------------------------------------------------------------------------------------------------------------		
			
	#This is a secure message
    def secure_send(self, msg_json):
		""" Process a secure message from server """
		# Cipher: new private key + old public key
		msg = {'type': 'secure', 'sa-data':{}, 'payload':{}}
		new_public_key, self.new_private_key = keys.verify_cipher_suite(self.cipher_suite)
					
		new_master_secret = keys.generate_master_secret(self.server_public_key, self.new_private_key)		
		self.rand_client = os.urandom(32)
		new_final_master_secret = keys.generate_final_master_secret(new_master_secret, self.rand_client + self.rand_srv)
		ciphertext , client_iv = keys.encrypt(self.cipher_suite,new_final_master_secret,msg_json)
				
		msg['sa-data'] = {'hash': base64.b64encode(keys.message_authentication(self.cipher_suite, new_final_master_secret, ciphertext)),
			'iv': base64.b64encode(client_iv), 'random':base64.b64encode(self.rand_client)}
		msg['payload'] = {'ciphertext': base64.b64encode(ciphertext),'public_key': new_public_key}
		
		self.sock.send(msg)
		
    def secure_receive(self, msg_json): 
		""" Process a secure message from server """
		# Decipher: public key received + old private key
		ciphertext = base64.b64decode(msg_json['payload']['ciphertext'])
		public_key = keys.deserialize_public_key(base64.b64decode(msg_json['payload']['public_key']))
		server_hash = base64.b64decode(msg_json['sa-data']['hash'])
		server_iv = base64.b64decode(msg_json['sa-data']['iv'])
		server_random = base64.b64decode(msg_json['sa-data']['random'])
		new_master_secret = keys.generate_master_secret(public_key, self.new_private_key)
		new_final_master_secret = keys.generate_final_master_secret(new_master_secret,self.rand_client + server_random)
		client_hash = keys.message_authentication(self.cipher_suite, new_final_master_secret, ciphertext)
		self.server_public_key = public_key
		self.rand_srv = server_random

		msg_json['payload'] = keys.decrypt(self.cipher_suite,new_final_master_secret,ciphertext,server_iv)
		
		if (server_hash != client_hash):
			logging.warning('Client Hash and Server Hash do not match!')
			
		if msg_json['payload']['type'] == 'list':
			self.receive_list_clients(msg_json['payload'], self.id)
			
		elif msg_json['payload']['type'] == 'client-connect':
			self.receive_client_connect(msg_json['payload'])
		
		elif msg_json['payload']['type'] == 'client-disconnect':
			self.receive_client_disconnect(msg_json['payload'])	
		
		elif msg_json['payload']['type'] == 'client-com':
			self.receive_client_com(msg_json['payload'])
			
		elif msg_json['payload']['type'] == 'ack':
			self.receive_client_ack(msg_json['payload'])
			
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
		 client.cipher_suite = msg['ciphers']
		 
		 self.secure_send(msg)
		 
    def receive_client_connect(self, reply):
		""" Process a client-connect message from client (phase > 1) """
		msg = {'type':'client-connect'}			
				
		if reply['phase'] == 1:
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
			client.cipher_suite = msg['ciphers']
			msg['data'] = {}
					
			self.secure_send(msg)
			return
					
			
		if reply['phase'] == 2:
			client = self.clients[str(reply['src'])]
			
			if reply['ciphers'] not in client.cipher_suite:
				logging.warning('Does not support cipher spec!')
				return
				
			client.cipher_suite = reply['ciphers']
			
			client.public_key, client.private_key = keys.verify_cipher_suite(client.cipher_suite)
			client.random = os.urandom(32)
			msg['data'] = {'public_key': client.public_key, 'random': base64.b64encode(client.random)}
			
			msg['dst'] =  reply['src']
			msg['src'] =  reply['dst']
			msg['phase'] = reply['phase']+1
			msg['ciphers'] = reply['ciphers']
			
			self.secure_send(msg)
			return
			
		if reply['phase'] == 3:
			client = self.clients[str(reply['src'])]
			
			client.cipher_suite = reply['ciphers']

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
			
			self.secure_send(msg)
			return
			
			
		if reply['phase'] == 4:
			client = self.clients[str(reply['src'])]
			
			client.received_public_key = keys.deserialize_public_key(base64.b64decode(reply['data']['public_key']))
			client.client_client_master_secret = keys.generate_master_secret(client.received_public_key,client.private_key )
			client.received_random = base64.b64decode(reply['data']['random'])
			client.client_client_final_master = keys.generate_final_master_secret(client.client_client_master_secret,client.random+client.received_random )
			print 'Connection to the Client finished with sucess!\n'
			return
			
#---------------------------------------------------------------------------------------------------------------

    def send_client_com(self,dst,cleartext):
		""" Process a client-com message from client """
		msg = {'type':'client-com', 'src': self.id,'dst': dst, 'data': {}}
		# Client in session
		client = self.clients[str(dst)]
		 
		# Cipher: new private key + old public key
		client.new_public_key,client.new_private_key = keys.verify_cipher_suite(client.cipher_suite)
		client.client_client_master_secret = keys.generate_master_secret(client.received_public_key, client.new_private_key)
		client.random = os.urandom(32)
		client.client_client_final_master = keys.generate_final_master_secret(client.client_client_master_secret,client.received_random + client.random)
		 
		ciphertext ,iv = keys.encrypt(client.cipher_suite,client.client_client_final_master ,cleartext)
		client.digest = keys.message_authentication(client.cipher_suite, client.client_client_final_master, ciphertext)
		
		client.private_key = client.new_private_key
		 
		msg['data'] = {'hash':base64.b64encode(client.digest),
					   'iv' : base64.b64encode(iv),
					   'public_key': client.new_public_key,
					   'ciphertext': base64.b64encode(ciphertext),
					   'random': base64.b64encode(client.random)
					   }

		self.secure_send(msg)
		
		
    def receive_client_com(self,reply):
		""" Process a client-com message from client """
		# Client in session
		client = self.clients[str(reply['src'])]

		# Decipher: public key received + old private key
		ciphertext = base64.b64decode(reply['data']['ciphertext'])
		client.received_public_key = keys.deserialize_public_key(base64.b64decode(reply['data']['public_key']))
		digest = base64.b64decode(reply['data']['hash'])
		client.received_random = base64.b64decode(reply['data']['random'])
		iv = base64.b64decode(reply['data']['iv'])
		
		client.client_client_master_secret = keys.generate_master_secret(client.received_public_key, client.private_key)
		client.client_client_final_master = keys.generate_final_master_secret(client.client_client_master_secret, client.random + client.received_random)
		client.digest = keys.message_authentication(client.cipher_suite,client.client_client_final_master, ciphertext)
		client.public_key = client.received_public_key
		
		if client.digest != digest:
			 logging.warning('Client Hash and Server Hash do not match!')
			 
		cleartext = keys.decrypt(client.cipher_suite, client.client_client_final_master, ciphertext, iv)
		 
		print '__________________________________________\n'
		print 'Client:',str(reply['src']),'# ',cleartext
		print '__________________________________________\n'
		
		if cleartext != '':
			self.send_client_ack(reply['src'])
        	
#---------------------------------------------------------------------------------------------------------------		
    
    def send_client_disconnect(self, dest):
		""" Process a client-disconnect message from aclient """
		msg = {'type': 'client-disconnect', 'src': self.id, 'dst': dest, 'data': {}}
		self.secure_send(msg)		
			
				
    def receive_client_disconnect(self, reply):
		""" Process a client-disconnect message from calient (last phase) """
		self.delClient(str(reply['src']))
		print 'Client ', str(reply['src']) , ' disconnected!!'
		return		
			
#---------------------------------------------------------------------------------------------------------------	

    def send_client_ack(self,dst):
		 """ Process a ack message from a client """
		 msg = {'type': 'ack', 'src':self.id, 'dst': dst, 'data': None}
		 self.secure_send(msg)
		 
    def receive_client_ack(self,reply):
		""" Process a ack message from a client (last phase) """
		print '\nClient', str(reply['src']), 'received your message with sucess!\n'
		
#---------------------------------------------------------------------------------------------------------------		
				
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
		
def main():
	sock = mysocket()
	con = Connection()
	con.loop()
	sock.close()

if __name__ == '__main__':
    main()
