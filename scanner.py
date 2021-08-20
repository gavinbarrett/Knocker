import re
import socket
from time import sleep
from queue import Queue
from random import sample
from threading import Thread, Lock
from argparse import ArgumentParser

print_lock = Lock()
worker_queue = Queue()

def get_port_list(full_scan, evasive_scan):
	if full_scan:
		ports = list(range(1, 65535))
		if evasive_scan: return sample(ports, 65534)
	if evasive_scan: return sample(list(range(1, 9999)), 9998)
	return list(range(1, 9999))

def scan(target):
	# create a socket object to test the connection
	tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	try:
		# attempt to connect to the port
		conn = tcp_socket.connect_ex(target[0])
		with print_lock:
			# check for open tcp port
			if conn == 0:
				print(f'{target[0][1]} -> open')
	except:
		with print_lock:
			print(f'Error connecting to target')
	finally:
		# close the socket
		tcp_socket.close()
		# sleep for 1 second to help evade IDS detection
		if target[1]: sleep(1)

def port_scan(address, full, evasive):
	# generate a list of ports to scan
	ports = get_port_list(full, evasive)
	print(f'Scanning {address}')
	for t in range(10):
		scanner = Thread(target=scan_threader)
		scanner.daemon = True
		scanner.start()
	# put the targets into the queue
	for port in ports:
		worker_queue.put(((address, port), evasive))
	# wait for threads to finish
	worker_queue.join()

def scan_threader():
	while True:
		work = worker_queue.get()
		scan(work)
		worker_queue.task_done()

def parse():
	parser = ArgumentParser()
	parser.add_argument("-f", "--full", action="store_true")
	parser.add_argument("-e", "--evasive", action="store_true")
	parser.add_argument("address", action="store", help="Please add an IPv4 address")
	return parser.parse_args()

if __name__ == "__main__":
	try:
		parsed = parse()
		if not parsed.address or not re.match(r'^[0-9]{1,3}(\.[0-9]{1,3}){3}$', parsed.address): raise ValueError('Please enter an IPv4 address.')
		
		port_scan(parsed.address, parsed.full, parsed.evasive)
	except Exception as error:
		print(error)
