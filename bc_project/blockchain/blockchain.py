from collections import OrderedDict
import binascii
import Crypto
import Crypto.Random
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

import hashlib
import json
from time import time
from urllib.parse import urlparse
import uuid
from datetime import datetime

import requests
from flask import Flask, jsonify, request, render_template
from flask_cors import CORS

MINING_SENDER = "THE BLOCKCHAIN"
MINING_REWARD = 1
MINING_DIFFICULTY = 2

class Blockchain:
	def __init__(self):
		#create a array for saving the transaction information
		self.transactions = []
		#define the blockchain 
		self.chain = []
		#define the nodes are all unique 
		self.nodes = set()
		#to create a random unique id for the node
		self.node_id = str(uuid.uuid4()).replace('-','')
		#create the 1st block (genesis block)
		self.create_block(0, '00')

	def register_node(self, node_url):
		#to check if the url of the node has valid format before adding the node
		parsed_url = urlparse(node_url)
		#check if the netloc is empty
		if parsed_url.netloc:
			self.nodes.add(parsed_url.netloc)
		#check if the path if empty
		elif parsed_url.path:
			self.nodes.add(parsed_url.path)
		else:
			raise ValueError('Invalid URL')	

	def submit_transaction(self, sender_address, sender_ID, question, answer, signature):
		# add the transaction to the transaction lists if the signature is verified
		transaction = OrderedDict({
				'sender_address': sender_address,
				'sender_ID': sender_ID,
				'question': question,
				'answer': answer
			})

		#Reward for mining a block(will modified later)
		if sender_address == MINING_SENDER:
			self.transactions.append(transaction)
			return len(self.chain) + 1
		# manage transactions whether it is valid (verified)
		else:
			transaction_verification = self.verify_transaction_signature(sender_address, signature, transaction)
			if transaction_verification:
				self.transactions.append(transaction)
				return len(self.chain) + 1
			else:
				return False

	def verify_transaction_signature(self, sender_address, signature, transaction):
		# Check that the provided signature corresponds to transaction
		# signed by the public key (sender_address)
	 		
		#define the value of poublic key
		#RSA_KEY
		public_key = RSA.importKey(binascii.unhexlify(sender_address))
		#signer
		verifier = PKCS1_v1_5.new(public_key)
		h = SHA.new(str(transaction).encode('utf-8'))
		return verifier.verify(h, binascii.unhexlify(signature))


	def create_block(self, nonce, previous_hash):
		block = {
			'block_number': len(self.chain) + 1,
			'timestamp': time(),
			'transactions': self.transactions,
			'nonce': nonce,
			'previous_hash': previous_hash
		}  		

		#reset the transactions info
		self.transactions = []
		self.chain.append(block)
		return block

	def hash(self, block):
		# create a SHA-256 hash of a block
		# We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
		block_string = json.dumps(block, sort_keys = True).encode()

		return hashlib.sha256(block_string).hexdigest()


	def proof_of_work(self):
		# PoW algorithm
		last_block = self.chain[-1]
		last_hash = self.hash(last_block)

		nonce = 0
		while self.valid_proof(self.transactions, last_hash, nonce) is False:
			nonce += 1

		return nonce

	def valid_proof(self, transactions, last_hash, nonce, difficulty = MINING_DIFFICULTY):
		#chech if a hash value satisfies the mining conditions
		guess = (str(transactions) + str(last_hash) + str(nonce)).encode()
		guess_hash = hashlib.sha256(guess).hexdigest()

		return guess_hash[:difficulty] == '0'*difficulty #add nums of '0' basic on the value of DIFFICULTY

	def valid_chain(self, chain):
		# check if a blockchain is valid
		last_block = chain[0]
		current_index = 1

		while current_index < len(chain):
			block = chain[current_index]
			#check the hash value of the block is correct
			if block['previous_hash'] != self.hash(last_block):
				return False

			#check the PoW is correct
			#delete the reward transaction
			transactions = block['transactions'][:-1] #exclude the last transaction
			#to make sure that the dictionary is ordered. Or will have a different hash
			transaction_elements = ['sender_address', 'sender_ID', 'question', 'answer']
			# self.transactions ?
			transactions = [OrderedDict((k, transaction[k]) for k in transaction_elements) for transaction in transactions]
			
			if not self.valid_proof(transactions, block['previous_hash'], block['nonce'], MINING_DIFFICULTY):
				return False

			last_block = block
			current_index += 1

		return True

	def resolve_conflicts(self):
		#Resolve condlicts between blockchain's nodes
		#by replacing the chain with the logest one in the network

		neighbours = self.nodes
		new_chain = None

		max_length = len(self.chain)

		for node in neighbours:
			print('http://' + node + '/chain')
			response = requests.get('http://' + node + '/chain')

			if response.status_code == 200:
				length = response.json()['length']
				chain = response.json()['chain']

				if length > max_length and self.valid_chain(chain):
					max_length = length
				new_chain = chain

		if new_chain:
			self.chain = new_chain
			return True

		return False

class Client:

	# def addBalance(self, client_ID):
    # 	self.balance[client_ID] = self.balance[client_ID] + 1
    # 	return self.balance

    def __init__(self):
        self.clients = {}
        # self.balance = {}
    
    def addClient(self, client_ID, pkey):
    	self.clients[pkey] = client_ID
    	# self.balance[client_ID] = 0
    	return self.clients

    def get_key(self, d, value):
    	val =  [k for k,v in d.items() if v == value]
    	return val

    def checkClient(self, client_ID, pkey):

        if pkey in self.clients.keys() and self.clients[pkey] == client_ID:
        	return "user exist"
        elif pkey in self.clients.keys() and self.clients[pkey] != client_ID:
        	return "id incorrect"
        elif pkey not in self.clients.keys() and pkey == self.get_key(self.clients, client_ID):
        	return "id used"
        else:
        	return "new user will be added"
        
        return self.clients


    def check_balance(self, client_ID, blockchain):
    	key = self.get_key(self.clients, client_ID)
    	p_key = key[0]

    	balance = 0
    	for i in blockchain:
    		transactions = i['transactions']
    		for j in transactions:
    			# print('p_key: ', p_key, 'class: ', type(p_key))
    			# print('sender_address: ', j['sender_address'], 'class: ', type(j['sender_address']))
    			if j['sender_address'] == p_key:
    				# print(p_key)
    				balance += 1
    				# print('balance: ', balance)

    	return balance




#Initiate the node
app = Flask(__name__)
CORS(app)

#Instantiate the Blockchain
blockchain = Blockchain()
client = Client()

@app.route('/')
def index():
	return render_template('./index.html')

@app.route('/configure')
def configure():
	return render_template('./configure.html')

@app.route('/checkID', methods = ['POST'])
def check_ID():
	sender_id = request.form['sender_ID']
	sender_pkey = request.form['sender_address']
	sender_id = str(sender_id).lower()
	print(sender_pkey)
	print(sender_id)
	if client.checkClient(sender_id, sender_pkey) == "id incorrect":
		response = {'message': "id incorrect"}
		print('id incorrect')
		return jsonify(response)
	elif client.checkClient(sender_id, sender_pkey) == "id used":
		response = {'message': "id used"}
		print('id used')
		return jsonify(response)
	elif client.checkClient(sender_id, sender_pkey) == "user exist":
		response = {'message': "user info correct"}
		print('user correct')
		return jsonify(response)
	elif client.checkClient(sender_id, sender_pkey) == "new user will be added":
		client.addClient(sender_id, sender_pkey)
		response = {'message': 'New ID added'}
		print('new id')
		return jsonify(response), 200

@app.route('/viewBalance', methods = ['POST'])
def viewBalance():
	sender_id = request.form['user_id']
	sender_id = str(sender_id).lower()
	if client.get_key(client.clients, sender_id) == []:
		response = {'message': 'ID not exist'}
		return jsonify(response)
	else:	
		response = {'message': client.check_balance(sender_id, blockchain.chain)}
		# print(client.check_balance(sender_id, blockchain.chain))
		return jsonify(response)


@app.route('/transactions/new', methods = ['POST'])
def new_transaction():
	values = request.form
	#check the required fields are in the POST'ed data
	required = ['sender_address', 'sender_ID', 'question', 'answer', 'signature']
	if not all(k in values for k in required):
		return 'Missing values', 400

	transaction_result = blockchain.submit_transaction(values['sender_address'], values['sender_ID'], values['question'], values['answer'], values['signature'])
	if transaction_result == False:
		response = {'message': 'Invalid Transaction!'}
		return jsonify(response), 406
	else:
		# name = values['sender_ID']
		# sender_id = values['sender_ID']
		# sender_id = str(sender_id).lower()
		# client.addBalance(sender_id)
		response = {
			'message': 'Transaction will be added to Block' + str(transaction_result)
		}

		return jsonify(response), 201

@app.route('/transactions/get', methods = ['GET'])
def get_transactions():
	#get transactions from transactions pool
	transactions = blockchain.transactions

	response = {'transactions': transactions}
	return jsonify(response), 200

@app.route('/chain', methods = ['GET'])
def full_chain():
	response = {
		'chain': blockchain.chain,
		'length': len(blockchain.chain)
	}

	return jsonify(response), 200

@app.route('/mine', methods = ['GET'])
def mine():
	transactions = blockchain.transactions
	#run the def: proof_of_work to get the next proof
	
	#get the last block
	last_block = blockchain.chain[-1]
	#calculate the value of the nonce
	nonce = blockchain.proof_of_work()
	if transactions == []:
		response = {
			'message': 'There is no unmined information'
		}
	else:
		#to create the reward for mining the block 
		#regard the rewarding as a extra transaction in that node
		blockchain.submit_transaction(
			sender_address =  MINING_SENDER,
			sender_ID = blockchain.node_id,
			question = None,
			answer = None,
			signature = "")
		#get the next hash base on the current block
		previous_hash = blockchain.hash(last_block)
		#create the new block

		block = blockchain.create_block(nonce, previous_hash)

		#set the response info
		response = {
			'message': 'New Block Created',
			'block_number': block['block_number'],
			'transactions': block['transactions'],
			'nonce': block['nonce'],
			'previous_hash': block['previous_hash']
		}
	return jsonify(response), 200

@app.route('/nodes/register', methods = ['POST'])
def register_nodes():
	values = request.form
	nodes = values.get('nodes').replcae(" ","").split(',')

	if nodes is None:
		return "Error: Please supply a valid list of nodes", 400

	for node in nodes:
		blockchain.register_node(node)

	response = {
		'message': 'New nodes have been added',
		'total_nodes': [node for node in blockchain.nodes]
	}

	return jsonify(response), 201

@app.route('/nodes/resolve', methods = ['GET'])
def consensus():
	replaced = blockchain.resolve_conflicts()
	timer = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
	if replaced:
		response = {
			'date': 'Verify Date: ' + timer,
			'message': 'Our chain was replaced',
			'chain': blockchain.chain
		}
	else:
		response = {
			'date': 'Verify Date: '+ timer,
			'message': 'Our chain is authoritative',
			'chain' : blockchain.chain
		}

	return jsonify(response), 200

@app.route('/nodes/get', methods = ['GET'])
def get_nodes():
	nodes = list(blockchain.nodes)
	response = {'nodes': nodes}
	return jsonify(response), 200




if __name__ == '__main__':
		from argparse import ArgumentParser

		parser = ArgumentParser()
		parser.add_argument('-p', '--port', default = 5000, type = int, help = 'port to listen on')	
		args = parser.parse_args()
		port = args.port 
		app.debug = True
		app.run(host = '127.0.0.1', port = port)

# first = None
# second = 1
# if first:


# parsed_tuple = urlparse("http:///search?hl=en&q=urlparse&btnG=Google+Search")

# print(parsed_tuple)
# if parsed_tuple.netloc:
# 	print('netloc')
# elif parsed_tuple.path:
# 	print('path')
# else:
# 	print('invalid url')

# print('0'*2)
# a = [1,2,3,4,5,6,7,8,9]

# print(a[:6])
# a = {'dog': 'eric', 'cat': 'Tome', 'rat': 'Li'}
# print(a['dog'])