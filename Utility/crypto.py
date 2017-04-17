#!/usr/bin/python2.7
import sys, json, os, binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from base64 import b64encode

style = ["\033[1;3" + str(i) + "m" for i in range(7)]
style_default = "\033[0m"


#############Generate Hash ###########################################
def generate_hash(message):
    try:        
        digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
        digest.update(message)
        msg_digest = digest.finalize()
        return msg_digest.encode('base-64')
    except:
        return -1


##############Generate RSA Keys#######################################
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


##############Encryption using RSA#######################################
def rsa_encrypt(message,public_key):
    if len(message) > 256 :
        x = len(message)/175
        cipher = ''
        for i in range(1,x+2):
            plaintext = message[(i-1)*175:i*175]
            ciphertext = public_key.encrypt(plaintext,padding.OAEP(mgf=padding.MGF1(
            	algorithm=hashes.SHA512()),algorithm=hashes.SHA256(),label=None))
            cipher  += str(ciphertext)
    else:    
        ciphertext = public_key.encrypt(message,padding.OAEP(mgf=padding.MGF1(
        	algorithm=hashes.SHA512()),algorithm=hashes.SHA256(),label=None))
        return ciphertext
        #SHA512 and SHA256 are used with RSA encryption for G and H functions.
    return cipher


##############Decryption using RSA #######################################
def rsa_decrypt(cipher,private_key):
    try:
        plaintext = private_key.decrypt(cipher,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),algorithm=hashes.SHA256(),label=None))
        return plaintext
    except:
        return -1


##############Encryption using AES256 #######################################
def aes_encrypt(aeskey, plaintext, associated_data):
    try:
        iv = os.urandom(16)
        encryptor = Cipher(algorithms.AES(aeskey),modes.GCM(iv),backend=default_backend()).encryptor()
        encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize() 
        return str(iv)+ str(encryptor.tag)+str(associated_data)+str(ciphertext)
    except:
        return -1
    


##############Decryption using AES256 #######################################
def aes_decrypt(key, associated_data, iv, ciphertext, tag):
    try :
        decryptor = Cipher(algorithms.AES(key),modes.GCM(iv, tag),backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(associated_data)
        return decryptor.update(ciphertext) + decryptor.finalize()
    except :
        return -1

##############Generate DH keys #######################################
# 2048-bit MODP Group - source -https://www.ietf.org/rfc/rfc3526.txt
def generate_dh_keys():
    prime = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC7402\
0BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C\
245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F2411\
7C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F836\
55D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA1821\
7C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF69\
55817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF'    
    g = 2
    p = int(prime,16)
    return g,p

##############Load Private key from Certificate #######################################
def load_private_key(server_private_key):
	try :
	    with open(server_private_key,"rb") as private_key_file:
	        private_key = serialization.load_pem_private_key(private_key_file.read(), password=None,
	                                                             backend=default_backend())
	        private_key_file.close()
	        return private_key
	except:
	    print "Error while getting private key from file!!!...\nExiting!!!..."
	    sys.exit(0)
##############Load Public key from Certificate #######################################
def load_public_key(server_public_key):
	try:
	    with open(server_public_key, "rb") as public_key_file:
	        public_key = serialization.load_der_public_key(public_key_file.read(), backend=default_backend())
	        public_key_file.close()
	        return public_key
	except:
	    print "Error while getting the public key from file!!!...\nExiting!!!..."
	    sys.exit(0)

############## #######################################
############## #######################################