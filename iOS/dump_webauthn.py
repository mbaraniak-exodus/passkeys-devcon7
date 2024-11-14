import sqlite3
import binascii
db = sqlite3.connect("keychain-2.db")
cur = db.cursor()
req = cur.execute("SELECT rowid, hex(data) FROM keys WHERE agrp='com.apple.webkit.webauthn'")
res = req.fetchall()
for item in res:
    f = open(str(item[0]) + ".bin", "wb")
    f.write(binascii.unhexlify(item[1])[4:])
    f.close()

