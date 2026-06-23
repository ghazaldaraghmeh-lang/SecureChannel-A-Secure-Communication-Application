from hmac_ref import hmac_sha256
import hmac
import hashlib

key = bytes([0x0b] * 20)
msg = b"Hi There"

your = hmac_sha256(key, msg).hex()
ref  = hmac.new(key, msg, hashlib.sha256).hexdigest()

print("Your :", your)
print("Ref  :", ref)
print("Match:", your == ref)