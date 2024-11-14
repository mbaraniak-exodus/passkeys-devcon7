import ccl_bplist
from io import BytesIO
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
from pyasn1.codec.der.decoder import decode
import binascii
import subprocess
import time
import sqlite3
import sys
import ItemV8_pb2
import struct

def decrypt_bplist(data, key):
	bplist = BytesIO(data)
	plistRaw = ccl_bplist.load(bplist)
	plist = ccl_bplist.deserialise_NsKeyedArchiver(plistRaw, parse_whole_structure=True)
	gcm = AES.new(key, AES.MODE_GCM, plist['root']['SFInitializationVector'])
	data = gcm.decrypt_and_verify(plist['root']['SFCiphertext'], plist['root']['SFAuthenticationCode'])
	return data	

def decode_der(data):
	result = {}	
	der_data = decode(data)[0]
	for k in der_data:
		if 'Octet' in str(type(k[1])):
			result[str(k[0])] = bytes(k[1])
		else:
			result[str(k[0])] = str(k[1])
	return result

def unwrap_key(ip, password, key, keyclass):
    ssh = subprocess.Popen([
        "sshpass",
        "-p",
        password,
        "ssh",
        "root@" + ip,
        "/tmp/keyclass_unwrapper",
        binascii.hexlify(key).decode("ascii"),
        str(int(keyclass))
    ],
    shell=False,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE)
    time.sleep(0.1)
    out = ssh.stdout.readlines()
    while out == 0:
        out = ssh.stdout.readlines()
        time.sleep(1)
    if len(out) > 0:
        out = binascii.unhexlify(out[0])
        if struct.unpack('<L', out[0:4])[0] == 0:
            raise Exception("Decryption error, wrong device/key - " + binascii.hexlify(out).decode('ascii'))
        return out
    raise Exception("Failed to decrypt")

IP = "192.168.1.10"
PASSWORD = "alpine"

f = open(sys.argv[1], "rb")
data = f.read()
item = ItemV8_pb2.ItemV8()
item.ParseFromString(data)

db = sqlite3.connect("keychain-2.db")
cur = db.cursor()
req = cur.execute("SELECT data FROM metadatakeys WHERE keyclass='" + str(item.keyclass) + "'")
res = req.fetchone()

key = unwrap_key(IP, PASSWORD, res[0], item.keyclass)[:32]
key2 = unwrap_key(IP, PASSWORD, item.secretData.keyReference.wrappedKey, item.keyclass)[:32]


keyMeta = decrypt_bplist(item.encryptedMetadata.encryptedMetadataKey, key)
data = decrypt_bplist(item.encryptedMetadata.encryptedMetadata, keyMeta)
result = decode_der(data)
print(result)
secretData = decrypt_bplist(item.secretData.encryptedData, key2)
result = decode_der(secretData)
print(result)
pubKey = result['v_Data'][0:65]
privateKey = result['v_Data'][65:]
print("Public key " + binascii.hexlify(pubKey).decode('ascii'))
print("Private key " + binascii.hexlify(privateKey).decode('ascii'))
key = ECC.construct(d=int(binascii.hexlify(privateKey), 16), curve="P-256")
if key.public_key().export_key(format="raw") != pubKey:
    raise Exception("Public key doesn't match private key")

