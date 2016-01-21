# rsa.py

## about

rsa.py is an implementation of the RSA algorithm written in python 3. It should probably only be used for fun and is available under the MIT License.

## use

````python
import rsa

key_factory = rsa.KeyFactory(1024) #create a key factory of 1024 bits
pub = rsa.PubKey(key_factory) #create the public key from  key_factory
priv = rsa.PrivKey(key_factory) #create the private key from key_factory

encrypted_data = pub.encrypt(42) #encrypt the number 42
assert priv.decrypt(encrypted_data) == 42 #decrypting encrypted_data should give you 42
````
