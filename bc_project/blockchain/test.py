# t1 = {'li':1}
# t2 = {'li':3,'mike':2}
# t3 = {'li':3}

# transactions = [t1,t2,t3]
# block ={'block_num':1, 'transactions': transactions}
# chain = [block]
# balance = 0

# for i in chain:
# 	transactions = i['transactions']
# 	for j in transactions:
# 		if j['li'] == 3:
# 			balance += 1

# print(balance)

# print(chain[0]['transactions'][0]['li'])
# print(block['transactions'][0])
# print(transactions[0])

a = {'one':1, 'two':2}
def get_key(d, value):
   	return [k for k,v in d.items() if v == value]

print(get_key(a,3))
# if get_key(a,3) == []:
# 	print('empty')