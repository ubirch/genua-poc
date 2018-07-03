#!/usr/local/bin/python3

import hashlib
import logging
import socket

import ed25519
import msgpack

TCP_IP = '192.168.2.65'
TCP_PORT = 8080
BUFFER_SIZE = 1024

verifying_key = None

# PUBKEY = 'ad3dbc020b9f940c670cea715fb20f2f025d710eeb846b807d8953fc146d5a3e'
# verifying_key = ed25519.VerifyingKey(PUBKEY, encoding="hex")

logging.basicConfig(format='%(asctime)s %(name)20.20s %(levelname)-8.8s %(message)s', level=logging.DEBUG)
log = logging.getLogger(__name__)
log.info('ubirch Genua PoC (sensor)')

try:
    f = open("sensordata.txt", "a+")
except IOError as e:
    print('File Error', e)
    exit(1)

# create an INET, STREAMing socket
serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# bind the socket to a public host, and a well-known port
serversocket.bind((TCP_IP, TCP_PORT))
# become a server socket
serversocket.listen(10)

while True:
    # accept connections from outside
    (clientsocket, address) = serversocket.accept()
    # print ('Connection address:', address)
    # now do something with the clientsocket
    # in this case, we'll pretend this is a threaded server
    data = clientsocket.recv(BUFFER_SIZE)
    if not data: break
    with open("sensordata.txt", "a+") as f:
        decoded = bytes.decode(data)
        f.write(decoded)
        (f1, f2) = decoded.split("|")
        #       f2 hexa and msgpack encoded

        sig = None
        if (f2[0:2] == "95"):
            # Key
            (ver, uuid, typ, pl, sig) = msgpack.unpackb(bytes.fromhex(f2))
            PUBKEY = pl[b'pubKey']
            verifying_key = ed25519.VerifyingKey(PUBKEY)
            log.info("New pubKey: {}".format(verifying_key.to_ascii(encoding="hex")))
        elif (f2[0:2] == "96"):
            # Data
            (ver, uuid, psig, typ, pl, sig) = msgpack.unpackb(bytes.fromhex(f2))
        else:
            f.write("ERROR verifying Ed25519 signature\n")

        try:
            verifying_key.verify(sig, hashlib.sha512(bytes.fromhex(f2)[0:-67]).digest())
        except Exception as e:
            log.info("Ed25519 signature failed: {}".format(e))
    clientsocket.close()
