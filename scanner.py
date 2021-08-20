import re
import sys
import socket
from queue import Queue
from threading import Thread, Lock

print_lock = Lock()
worker_queue = Queue()

def scan(target):
	tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		conn = tcp_socket.connect_ex(target)
		with print_lock:
			if conn == 0:
				print(f'{target[1]} -> open')
	except:
		with print_lock:
			print(f'Error connecting to target')
	finally:
		tcp_socket.close()

def port_scan(address):
	print(f'Scanning {address}')
	# generate a list of ports to scan
	ports = list(range(10, 10000))
	#ports = [22, 25, 53, 143, 110, 80, 443, 8080, 9100]
	for t in range(10):
		scanner = Thread(target=scan_threader)
		scanner.daemon = True
		scanner.start()
	# put the targets into the queue
	for port in ports:
		worker_queue.put((address, port))
	# wait for threads to finish
	worker_queue.join()

def scan_threader():
	while True:
		work = worker_queue.get()
		scan(work)
		worker_queue.task_done()

if __name__ == "__main__":
	try:
		args = sys.argv
		if len(args) != 2 or not re.match(r'^[0-9]{1,3}(\.[0-9]{1,3}){3}$', args[1]): raise ValueError('Please enter an IPv4 address.')
		
		port_scan(args[1])
	except:
		print('error')
