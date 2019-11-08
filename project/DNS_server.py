from __future__ import print_function
import argparse
from dnslib import RR, A, QTYPE, TXT
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger, DNSRecord
import time

class Resolver(BaseResolver):

    def __init__(self, address="127.0.0.1"):
        self.address = address
        self.TXTrecord_data = None #data the TXT record contains in case of dns-01 queries to DNS server
        self.TXTrecord_domain = None

    def updateTXT(self, data, domain):
        self.TXTrecord_data = data
        self.TXTrecord_domain = domain

    def resolve(self, request,handler):
        reply = request.reply()
        domain = request.q.qname
        if request.q.qtype == QTYPE.TXT: #acme server validates dns challenge
            reply.add_answer(RR(self.TXTrecord_domain, QTYPE.TXT, rdata=TXT(self.TXTrecord_data), ttl=100))
        else:
            reply.add_answer(RR(domain, QTYPE.A, rdata=A(self.address), ttl=100))
        #print("DNS SERVER REPLY: ",reply)
        return reply

    def start(self):
        logger = DNSLogger(prefix=False)
        udp_server = DNSServer(self, port=10053, address=self.address, logger=logger)
        udp_server.start_thread()


'''
def main():
    parser = argparse.ArgumentParser(description='Process some integers.')
    parser.add_argument('record')
    args = vars(parser.parse_args())
    logger = DNSLogger(prefix=False)
    print(args.get('record'))
    resolver = Resolver(args.get('record'))
    udp_server = DNSServer(resolver, port=10053, address=resolver.address, logger=logger)
    udp_server.start()

if __name__ == '__main__':
    main()
'''

