from rsa import *
size = 128

keys = gen_key_pair(size)

print ("public key: "+str(keys.public_key.key)+", "+str(keys.public_key.modulus))
print ("private key: "+str(keys.private_key.key)+", "+str(keys.private_key.modulus))

message = "hello world"
print ("message = "+message)

msg = str_to_int(message)
c = rsa_enc(keys.public_key, msg)
print ("encrypted = "+str(c))

m = rsa_dec(keys.private_key, c)
dec_str = int_to_str(m)
print ("decrypted = "+dec_str)
