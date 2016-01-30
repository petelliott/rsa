# rsa.py

## about

rsa.py is an implementation of the RSA algorithm written in python 3. It should probably only be used for fun and is available under the MIT License.

## use

````python
import rsa

key_factory = rsa.KeyFactory(1024) #create a key factory of 1024 bits
pub = rsa.PubKey(key_factory) #create the public key from  key_factory
priv = rsa.PrivKey(key_factory) #create the private key from key_factory

encrypted_data = pub.encrypt("hello world") #encrypt the String "hello world"
assert priv.decrypt(encrypted_data) == "hello world"
#decrypting encrypted_data should give you "hello world"

signature = priv.sign("hello world") #sign "hello world"
assert pub.verify(signature,"hello world") #verifies as True

#keys can be saved as strings
plain_text = str(pub)
pub2 = rsa.PubKey(plain_text)
````
