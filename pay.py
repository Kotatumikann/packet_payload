#_*_coding: utf-8 -*-
from datetime import datetime
from netfilterqueue import NetfilterQueue
def fileout(pkt):
	a=pkt.encode('hex')
	moji=str(a)
	time=datetime.now().strftime('%Y/%m/%d %H:%M:%S')
	length=len(moji)
	fp=open("test3.txt","w")
	fp.write(moji+'\n')
	fp.write(length)
	fp.write('\n')
	fp.close()

def print_and_accept(pkt):
	
	c=pkt.get_payload()
	print c
	pkt.accept()
	fileout(c)

def main():	
	nfqueue = NetfilterQueue()
	nfqueue.bind(2,print_and_accept)

	try:
		nfqueue.run()

	except KeyboardInterrupt:
		print

main()
