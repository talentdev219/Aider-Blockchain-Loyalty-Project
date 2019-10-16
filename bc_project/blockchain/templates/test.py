from datetime import datetime
import time

def timer(n):
	while True:
		print(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
		time.sleep(n)


timer(5)