#
# Scan.py
# ScapyStuff
#
# lukem1
#

from datetime import datetime
import logging
from scapy.all import *
import sys

conf.verb = 0
logger = logging.getLogger(__name__)
logger.setLevel(logging.WARNING)

def tcpSYN(target, ports, time=3, retries=0):
	"""
	Performs a TCP SYN scan of the specified ports on a host or subnet.
	
	Parameters:
	target: host or subnet to scan (ie scapy.net, 8.8.8.8, or 192.168.86.1/24)
	ports: port (ie 22), port range (ie (0, 100)), or port list (ie [22, 80, 443]) to scan 
	time: seconds until packet timeout
	retries: number of times to resend unanswered packets
	"""
	
	# Build the packets
	
	packets = IP(dst=target)/TCP(dport=ports, flags="S")
	
	# Send the packets and capture responses
	
	replies, noreplies = sr(packets, timeout=time, retry=retries)
	
	# Print results
	
	"""
	print("Answered Packets:")
	print(replies.summary())
	print("Unanswerd Packets:")
	print(noreplies.summary())
	"""
	
	hosts = set()
	results = {}
	
	for r in replies:
		p = r[1]
		try:
			ip = p[IP].src
			port = p[TCP].sport
			flags = p[TCP].flags
			
			state = "closed"
			if 'S' in flags:
				state = "open"
			
			if not ip in hosts:
				hosts.add(ip)
				results[ip] = "\nScan report for %s:\nHost is up!\n" % ip
			
			results[ip] += "%s %s\n" % (port, state)
		except:
			p.summary()
		
	for r in noreplies:
		ip = r[IP].dst
		port = r[TCP].dport
		
		if not ip in hosts:
			hosts.add(ip)
			results[ip] = "\nScan report for %s:\nHost appears down.\n" % ip
			
	print("Scan done at %s" % datetime.now())
	for h in hosts:
		print(results[h], end='')
	
	
	
if __name__ == "__main__":
	if len(sys.argv) < 3:
		print("Usage:\npython3 Scan.py [target] [port 1] [port 2] ... [port n]") 
	else:
		tcpSYN(sys.argv[1], [int(p) for p in sys.argv[2:]])
	
