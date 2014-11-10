#!/usr/bin/python3 -tt

# NXT Alias DNS resolver
# By mal <mal@sec.gd>
# Released under the GNU GPL v3

host = "127.0.0.1"
port = 1053
tlds = {"hype": (lambda x: "4973" + x)}
nxt_api_url = "http://127.0.0.1:7876/nxt"
ttl = 60*60*24*7

import signal
import asyncio
import requests
import traceback
from time import time
from ipaddress import IPv6Address
from twisted.names.dns import Message, RRHeader, Record_SOA, Record_AAAA

NOERROR  = 0
SERVFAIL = 2
NXDOMAIN = 3
REFUSED  = 5

@asyncio.coroutine
def respond(transport, data, addr=None):
    response = buildResponseBytes(data)
    if addr != None: # UDP
        transport.sendto(response, addr)
        # Closing UDP transport would be killing the listener
    else: # TCP
        transport.write(len(response).to_bytes(length=2, byteorder="big")+response)
        transport.close()

def buildResponseBytes(data):
    inMessage = Message()
    inMessage.fromStr(data)
    return(buildResponse(inMessage).toStr())

def buildResponse(inMessage):
    outMessage = Message(id=inMessage.id, answer=1, opCode=inMessage.opCode, recDes=1, recAv=1, auth=1, authenticData=1)
    outMessage.queries = inMessage.queries
    rcode = NOERROR
    querytlds = []
    for query in inMessage.queries:
        tld = query.name.name.decode("utf-8").lower().split(".")[-1]
        if not tld in tlds:
            if rcode != SERVFAIL:
                rcode = REFUSED
        if not tld in querytlds: # SOA even if wrong type
            querytlds.append(tld)
        if not (query.type == 28 or query.type == 255): # AAAA or ALL
            continue # NOERROR without record
        try:
            error, queryRRH = doQuery(query)
            if error:
                print("error", query.name.name.decode("utf-8"), error)
            if len(inMessage.queries) < 2:
                rcode = error
            elif error == NOERROR: # Don't change for NOERROR
                pass
            elif error == SERVFAIL or rcode == SERVFAIL: # SERVFAIL replaces all
                rcode = SERVFAIL
            elif error == REFUSED or rcode == REFUSED: # Refused replaces all but SERVFAIL
                rcode = REFUSED
            elif error == NXDOMAIN or rcode == NXDOMAIN: # NXDOMAIN
                rcode = NXDOMAIN
            else:
                print("Unexpected error from doQuery:", error)
                rcode = SERVFAIL
        except Exception as e:
            rcode = SERVFAIL
            print("oops", query, traceback.format_exc())
            outMessage.answers = []
            querytlds = []
            break
        if queryRRH != None:
            outMessage.answers.append(queryRRH)
    for tld in querytlds:
        outMessage.authority.append(RRHeader(
                name=tld,
                type=6, # SOA
                cls=query.cls,
                ttl=ttl,
                payload=Record_SOA(
                        mname=tld,
                        rname="", serial=int(time()/ttl),
                        refresh=ttl, retry=ttl, expire=ttl, minimum=ttl),
                        auth=True))
    outMessage.rCode = rcode
    return(outMessage)

def doQuery(query):
    components = query.name.name.decode("utf-8").lower().split(".")
    if len(components) < 2:
        return(SERVFAIL, None)
    tld = components[-1]
    if not tld in tlds:
        return(REFUSED, None)
    name = components[-2] # all subdomains resolve to main domain. good idea or no?
    for i in range(3):
        try:
            error, address = getIPv6Alias(tlds[tld](name))
            if error != NOERROR:
                return(error, None)
            if address == None:
                return(SERVFAIL, None)
            print(query.name.name.decode("utf-8"), address)
            payload=Record_AAAA(address=address)
            return(NOERROR, RRHeader(
                name=query.name.name,
                type=payload.TYPE,
                cls =query.cls,
                ttl =ttl,
                payload=payload,
                auth=True))
        except (ValueError, KeyError): # Probably HTTP request failed or HTTP server hiccuped
            continue
        raise Exception("doQuery loop passed without return or raise")
    raise Exception("doQuery failed repeatedly")

def getIPv6Alias(alias):
    for i in range(3):
        r = requests.post(nxt_api_url, data={"requestType": "getAlias", "aliasName": alias})
        if r.status_code == 200:
            break
    else: # HTTP request failed repeatedly
        return(SERVFAIL, None)
    json = r.json()
    if json.get("errorCode") == 5: # doesn't exist
        return(NXDOMAIN, None)
    if "aliasURI" in json:
        try:
            IPv6Address(json["aliasURI"])
        except ValueError:
            print("alias", alias, json["aliasURI"], "malformed ipv6 address")
            return(SERVFAIL, None) # Not an IPv6 address
        return(NOERROR, json["aliasURI"])
    else:
        return(SERVFAIL, None)

class DNSServer(asyncio.Protocol):
    TIMEOUT = 5.0
    h_timeout = None
    data = b''
    dataexpect = 0
    def connection_made(self, transport):
        self.transport = transport
    def data_received(self, data): # TCP
        if self.h_timeout:
            self.h_timeout.cancel()
        self.h_timeout = asyncio.get_event_loop().call_later(
                self.TIMEOUT, self.timeout)
        self.data += data
        if len(self.data) >= 2 and len(self.data)-2 >= int.from_bytes(self.data[:2], byteorder="big"):
            self.datagram_received(self.data[2:], addr=None)
    def datagram_received(self, data, addr): # UDP
        asyncio.get_event_loop().create_task(respond(self.transport, data, addr))
    def timeout(self): # TCP
        self.transport.close()
    def connection_lost(self, exc):
        if self.h_timeout:
            self.h_timeout.cancel()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGINT, loop.stop)
    loop.run_until_complete(loop.create_task(loop.create_datagram_endpoint(
            DNSServer, local_addr=(host, port))))
    loop.run_until_complete(loop.create_task(loop.create_server(
            DNSServer, host, port)))
    print("Running")
    try:
        loop.run_forever()
    finally:
        loop.close()
    print("\nQuitting")

