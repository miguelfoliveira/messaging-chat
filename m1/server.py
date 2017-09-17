# encoding: utf-8
#
# jpbarraca@ua.pt
# jmr@ua.pt 2016

# vim setings:
# :set expandtab ts=4

from socket import *
from select import *
import json
import sys
import time
import logging
import keys
import base64
import os
import logging

# Server address
HOST = ""   # All available interfaces
PORT = 8080  # The server port

BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024

STATE_NONE = 0
STATE_CONNECTED = 1
STATE_DISCONNECTED = 2

session_connected = False

class Client:
    count = 0

    def __init__(self, socket, addr):
        self.socket = socket
        self.bufin = ""
        self.bufout = ""
        self.addr = addr
        self.id = None
        self.sa_data = None
        self.level = 0
        self.state = STATE_NONE
        self.name = "Unknown"
        # Added
        self.cipher_suite = None
        self.private_key = None
        self.rand_server = None
        self.random_client = None
        self.final_master_secret = None
        self.received_public_key = None

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(id=%r addr:%s name:%s level:%d state:%d)" % (self.id, str(self.addr), self.name, self.level, self.state)

    def asDict(self):
        return {'name': self.name, 'id': self.id, 'level': self.level}

    def setState(self, state):
        if state not in [STATE_CONNECTED, STATE_NONE, STATE_DISCONNECTED]:
            return

        self.state = state

    def parseReqs(self, data):
        """Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket."""

        if len(self.bufin) + len(data) > MAX_BUFSIZE:
            logging.error("Client (%s) buffer exceeds MAX BUFSIZE. %d > %d", 
                (self, len(self.bufin) + len(data), MAX_BUFSIZE))
            self.bufin = ""

        self.bufin += data
        reqs = self.bufin.split(TERMINATOR)
        print reqs
        self.bufin = reqs[-1]
        return reqs[:-1]

    def send(self, obj):
        """Send an object to this client.
        """
        try:
            if obj['type'] == 'secure':
				new_public_key, new_private_key = keys.verify_cipher_suite(self.cipher_suite)
				#print type(self.received_public_key)
				new_master_secret = keys.generate_master_secret(self.received_public_key, new_private_key)
				self.rand_server = os.urandom(32)
				self.final_master_secret = keys.generate_final_master_secret(new_master_secret, self.random_client + self.rand_server)
				ciphertext, server_iv = keys.encrypt(self.cipher_suite,self.final_master_secret,obj['payload'])
				obj['payload'] = {'ciphertext': base64.b64encode(ciphertext),'public_key':new_public_key}
				server_hash = keys.message_authentication(self.cipher_suite,self.final_master_secret,ciphertext)
				obj['sa-data'] = {'hash': base64.b64encode(server_hash), 'iv': base64.b64encode(server_iv), 'random': base64.b64encode(self.rand_server) }
				self.private_key = new_private_key
				self.bufout += json.dumps(obj) + "\n\n"
            else:
				self.bufout += json.dumps(obj) + "\n\n"
				
        except:
            # It should never happen! And not be reported to the client!
            logging.exception("Client.send(%s)", self)

    def close(self):
        """Shuts down and closes this client's socket.
        Will log error if called on a client with closed socket.
        Never fails.
        """
        logging.info("Client.close(%s)", self)
        try:
            # Shutdown will fail on a closed socket...
            #self.socket.shutdown(SHUT_RDWR)
            self.socket.close()
        except:
            logging.exception("Client.close(%s)", self)

        logging.info("Client Closed")


class ChatError(Exception):
    """This exception should signal a protocol error in a client request.
    It is not a server error!
    It just means the server must report it to the sender.
    It should be dealt with inside handleRequest.
    (It should allow leaner error handling code.)
    """
    pass


def ERROR(msg):
    """Raise a Chat protocol error."""
    raise ChatError(msg)


class Server:
    def __init__(self, host, port):
        self.ss = socket(AF_INET, SOCK_STREAM)  # the server socket (IP \ TCP)
        self.ss.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.ss.bind((host, port))
        self.ss.listen(10)
        logging.info("Secure IM server listening on %s", self.ss.getsockname())
        # clients to manage (indexed by socket and by name):
        self.clients = {}       # clients (key is socket)
        self.id2client = {}   # clients (key is id)
        # Added
        self.public_key = None
        self.peer_public_key = None
        self.master_secret = None

    def stop(self):
        """ Stops the server closing all sockets
        """
        logging.info("Stopping Server")
        try:
            #self.ss.shutdown(SHUT_RDWR)
            self.ss.close()
        except:
            logging.exception("Server.stop")

        for csock in self.clients:
            try:
                self.clients[csock].close()  # Client.close!
            except:
                # this should not happen since close is protected...
                logging.exception("clients[csock].close")

        # If we delClient instead, the following would be unnecessary...
        self.clients.clear()
        self.id2client.clear()

    def addClient(self, csock, addr):
        """Add a client connecting in csock."""
        if csock in self.clients:
            logging.error("Client NOT Added: %s already exists", self.clients[csock])
            return

        client = Client(csock, addr)
        self.clients[client.socket] = client
        logging.info("Client added: %s", client)

    def delClient(self, csock):
        """Delete a client connected in csock."""
        if csock not in self.clients:
            logging.error("Client NOT deleted: %s not found", self.clients[csock])
            return

        client = self.clients[csock]
        assert client.socket == csock, "client.socket (%s) should match key (%s)" % (client.socket, csock)
        #del self.id2client[client.id]

        if client.id in self.id2client.keys():
            del self.id2client[client.id]

        del self.clients[client.socket]
        client.close()
        logging.info("Client deleted: %s", client)

    def accept(self):
        """Accept a new connection.
        """
        try:
            csock, addr = self.ss.accept()
            self.addClient(csock, addr)
        except:
            logging.exception("Could not accept client")

    def flushin(self, s):
        """Read a chunk of data from this client.
        Enqueue any complete requests.
        Leave incomplete requests in buffer.
        This is called whenever data is available from client socket.
        """
        client = self.clients[s]
        data = None
        try:
            data = s.recv(BUFSIZE)
            logging.info("Received data from %s. Message:\n%r", client, data)
        except:
            logging.exception("flushin: recv(%s)", client)
            logging.error("Received invalid data from %s. Closing", client)
            self.delClient(s)
        else:
            if len(data) > 0:
                reqs = client.parseReqs(data)
                for req in reqs:
                    self.handleRequest(s, req)
            else:
                self.delClient(s)

    def flushout(self, s):
        """Write a chunk of data to client.
        This is called whenever client socket is ready to transmit data."""
        if s not in self.clients:
            # this could happen before, because a flushin might have deleted the client
            logging.error("BUG: Flushing out socket that is not on client list! Socket=%s", str(s))
            return

        client = self.clients[s]
        try:
            sent = client.socket.send(client.bufout[:BUFSIZE])
            logging.info("Sent %d bytes to %s. Message:\n%r", sent, client, client.bufout[:sent])
            client.bufout = client.bufout[sent:]  # leave remaining to be sent later
        except:
            logging.exception("flushout: send(%s)", client)
            # logging.error("Cannot write to client %s. Closing", client)
            self.delClient(client.socket)

    def loop(self):
        while True:
            # sockets to select for reading: (the server socket + every open client connection)
            rlist = [self.ss] + self.clients.keys()
            # sockets to select for writing: (those that have something in bufout)
            wlist = [ sock for sock in self.clients if len(self.clients[sock].bufout)>0 ]
            logging.debug("select waiting for %dR %dW %dX", len(rlist), len(wlist), len(rlist))
            (rl, wl, xl) = select(rlist, wlist, rlist)
            logging.debug("select: %s %s %s", rl, wl, xl)

            # Deal with incoming data:
            for s in rl:
                if s is self.ss:
                    self.accept()
                elif s in self.clients:
                    self.flushin(s)
                else:
                    logging.error("Incoming, but %s not in clients anymore", s)

            # Deal with outgoing data:
            for s in wl:
                if s in self.clients:
                    self.flushout(s)
                else:
                    logging.error("Outgoing, but %s not in clients anymore", s)

            for s in xl:
                logging.error("EXCEPTION in %s. Closing", s)
                self.delClient(s)

    def handleRequest(self, s, request):
        """Handle a request from a client socket.
        """
        client = self.clients[s]
        try:
            logging.info("HANDLING message from %s: %r", client, repr(request))

            try:
                req = json.loads(request)
            except:
                return

            if not isinstance(req, dict):
                return

            if 'type' not in req:
                return

            if req['type'] == 'ack':
                return  # Ignore for now

            client.send({'type': 'ack'})

            if req['type'] == 'connect':
                self.processConnect(client, req)
            elif req['type'] == 'secure':
                self.processSecure(client, req)

        except Exception, e:
            logging.exception("Could not handle request")

    def clientList(self):
        """
        Return the client list
        """
        cl = []
        for k in self.clients:
			cl.append(self.clients[k].asDict())
        return cl

    def processConnect(self, sender, request):
        """
        Process a connect message from a client
        """
		
        if sender.state == STATE_CONNECTED:
            logging.warning("Client is already connected: %s" % sender)
            return

        if not all (k in request.keys() for k in ("name", "ciphers", "phase", "id")):
            logging.warning("Connect message with missing fields")
            return

        msg = {'type': 'connect', 'phase': request['phase'] + 1, 'ciphers': ['NONE']}

        if len(request['ciphers']) > 1 or 'NONE' not in request['ciphers']:
            logging.info("Connect continue to phase " + str(msg['phase']))
            
            # Server ciphers
            msg['ciphers'] = ['ECDHE-AES128_CTR-SHA256', 'DHE-AES128_CTR-SHA256', 'ECDHE-AES256_CTR-SHA384']
            
            #begin ECDHE handshake
            
            # Cipher_suite selection mode
            for c in msg['ciphers']:
                if c in request['ciphers']:
                    sender.cipher_suite = c
                    break       
                    
            if sender.cipher_suite == None:
				logging.warning('\nCipher Spec not supported!')
				return        

            msg['ciphers'] = sender.cipher_suite
            msg['data'] = {}
            public_key, sender.private_key = keys.verify_cipher_suite(sender.cipher_suite)
                     
            if request['phase'] == 3:
				# deserialize client public key
				peer_public_key = keys.deserialize_public_key(base64.b64decode(request['data']['public_key']))
				# generate master secret
				self.master_secret = keys.generate_master_secret(peer_public_key, sender.private_key)
				#print type(self.master_secret )
				# server random
				sender.rand_server = os.urandom(32)
				# get client random
				rand_client = base64.b64decode(request['data']['client_random'])
				msg['data'] = {'public_key': public_key, 'server_random': base64.b64encode(sender.rand_server)}
				# generate final master key(master_key, rand_client+rand_server)
				sender.final_master_secret = keys.generate_final_master_secret(self.master_secret, rand_client+sender.rand_server)
				
				session_connected = True
				
				if session_connected:
					#print type(request['id'])
					self.id2client[int(request['id'])] = sender
					sender.id = request['id']
					sender.name = request['name']
					sender.state = STATE_CONNECTED
					logging.info("Client %s Connected" % request['id'])
					        
            sender.send(msg)
								

    def processList(self, sender, request):
        """
        Process a list message from a client
        """
        if sender.state != STATE_CONNECTED:
            logging.warning("LIST from disconnected client: %s" % sender)
            return
            
       
        sender.send({'type': 'secure', 'payload': {'type': 'list', 'data': self.clientList()}})

    def processSecure(self, sender, request):
        """
        Process a secure message from a client
        """
        
        if sender.state != STATE_CONNECTED:
            logging.warning("SECURE from disconnected client: %s" % sender)
            return

        if 'payload' not in request:
            logging.warning("Secure message with missing fields")
            return
        
        # This is a secure message.
        # TODO: Inner message is encrypted for us. Must decrypt and validate. 
        ciphertext =  base64.b64decode(request['payload']['ciphertext'])
        sender.received_public_key = keys.deserialize_public_key(base64.b64decode(request['payload']['public_key']))
        client_hash = base64.b64decode(request['sa-data']['hash'])
        client_iv = base64.b64decode(request['sa-data']['iv'])
        sender.random_client = base64.b64decode(request['sa-data']['random'])
        new_master_secret = keys.generate_master_secret(sender.received_public_key, sender.private_key)
        sender.final_master_secret = keys.generate_final_master_secret(new_master_secret,sender.random_client + sender.rand_server)
        server_hash = keys.message_authentication(sender.cipher_suite,sender.final_master_secret,ciphertext)
        
        if(client_hash != server_hash):
			logging.warning('Client Hash and Server Hash do not match!')
        
        request['payload'] = keys.decrypt(sender.cipher_suite,sender.final_master_secret,ciphertext,client_iv)
        
        if 'type' not in request['payload'].keys():
            logging.warning("Secure message without inner frame type")
            return

        if request['payload']['type'] == 'list':
            self.processList(sender, request['payload'])
            return

        if not all (k in request['payload'].keys() for k in ("src", "dst")):
			return
         
        if not int(request['payload']['dst']) in self.id2client.keys():
            logging.warning("Message to unknown client: %s" % request['payload']['dst'])
            return
          
        dst = self.id2client[int(request['payload']['dst'])]

        dst_message = {'type': 'secure', 'payload': request['payload']}
        dst.send(dst_message)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    serv = None
    while True:
        try:
            logging.info("Starting Secure IM Server v1.0")
            serv = Server(HOST, PORT)
            serv.loop()
        except KeyboardInterrupt:
            serv.stop()
            try:
                logging.info("Press CTRL-C again within 2 sec to quit")
                time.sleep(2)
            except KeyboardInterrupt:
                logging.info("CTRL-C pressed twice: Quitting!")
                break
        except:
            logging.exception("Server ERROR")
            if serv is not (None):
                serv.stop()
            time.sleep(10)
