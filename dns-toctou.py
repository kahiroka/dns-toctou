#!/usr/bin/env python3
# Author: Human beings feat. ChatGPT with GitHub Copilot
import socket
import struct
import os
import json
import argparse
import subprocess

class DNSServer:
    def __init__(self, config=None, debug=False):
        if config is None:
            file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.json')
        else:
            file = config
        self.debug = debug
        self.flag = False

        try:
            with open(file) as f:
                self.config = json.load(f)
                if self.debug:
                    print(json.dumps(self.config, indent=4))
        except FileNotFoundError:
            print(f"Config file {file} not found")
            exit(1)

    def handle_query(self, data, addr):
        # analyze DNS header
        header = struct.unpack('!6H', data[:12])
        transaction_id, flags, qdcount, ancount, nscount, arcount = header

        # analyze DNS query
        query = data[12:]
        domain_parts = []
        while True:
            length = query[0]
            if length == 0:
                query = query[1:]
                break
            domain_parts.append(query[1:1+length].decode())
            query = query[1+length:]
        domain_name = '.'.join(domain_parts)

        # get query type and class
        qtype, qclass = struct.unpack('!2H', query[:4])

        ipaddrs = []
        pause = False
        cond = False
        flag = False
        execs = []
        response = b''
        # check if domain is in the list
        for record in self.config['domains']:
            if domain_name.endswith(record['domain']):
                if self.debug:
                    print(record)
                ipaddrs = record['ipaddrs']
                if 'pause' in record:
                    pause = record['pause']
                if 'cond' in record:
                    cond = record['cond']
                if 'flag' in record:
                    flag = record['flag']
                if 'execs' in record:
                    execs = record['execs']
                break

        offset = 0
        if pause:
            ret = input("Press Enter or input answer offset: ")
            try:
                offset = int(ret)
            except ValueError:
                offset = 0

        if (not cond) or (cond and self.flag):
            if len(execs) != 0:
                print(execs[0])
                result = subprocess.run([execs[offset]], shell=True, capture_output=True, text=True)
                print(result.stdout)

        if cond and self.flag:
            self.flag = False

        if flag:
            self.flag = True

        if len(ipaddrs) != 0: 
            response_data = ipaddrs[offset:]
            print(f"Responding to query for {domain_name} with {response_data}")
            response = self.build_response(transaction_id, domain_name, response_data)
        else:
            # forward to upstream DNS
            print(f"Forwarding query for {domain_name} to upstream DNS")
            response = self.forward_to_upstream(data)

        # response to client
        self.sock.sendto(response, addr)

    def build_response(self, transaction_id, domain_name, response_data):
        flags = 0x8180  # standard query response, no error
        qdcount = 1
        ancount = len(response_data)
        nscount = 0
        arcount = 0

        header = struct.pack('!6H', transaction_id, flags, qdcount, ancount, nscount, arcount)

        question = b''
        for part in domain_name.split('.'):
            question += struct.pack('B', len(part)) + part.encode()
        question += struct.pack('BHH', 0, 1, 1)[:-1] # remove extra byte

        answer = b''
        for ipaddr in response_data:
            answer += b'\xc0\x0c'  # compression pointer
            answer += struct.pack('!2H', 1, 1)  # QTYPE and QCLASS
            answer += struct.pack('!I', 60)  # TTL
            answer += struct.pack('!H', 4)  # RDLENGTH
            answer += socket.inet_aton(ipaddr)

        return header + question + answer

    def forward_to_upstream(self, query_data):
        upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        upstream_sock.settimeout(5)
        upstream_sock.sendto(query_data, (self.config['upstream_dns'], 53))
        
        try:
            response_data, _ = upstream_sock.recvfrom(512)
        except socket.timeout:
            print("Upstream DNS timeout")
            response_data = b''
        
        upstream_sock.close()
        return response_data

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.config['host'], self.config['port']))

        print(f"DNS server is running on {self.config['host']}:{self.config['port']}")
        while True:
            data, addr = self.sock.recvfrom(512)
            self.handle_query(data, addr)

def getArgs():
    usage = 'python3 {} [-c CONFIG]'.format(__file__)
    parser = argparse.ArgumentParser(usage=usage)
    parser.add_argument('-c', '--config', help='Config file', default=None)
    parser.add_argument('-d', '--debug', help='Debug mode', action='store_true')
    return parser.parse_args()

def main():
    args = getArgs()
    dns_server = DNSServer(config=args.config, debug=args.debug)
    dns_server.start()

if __name__ == '__main__':
    main()
