"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
from util import RSA_to_json_string, RSA_from_json_string

def path_join(*strings):
    """Joins a list of strings putting a "/" between each.

    :param strings: a list of strings to join
    :returns: a string
    """
    return '/'.join(strings)

class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
    
    def resolve(self, uid):
        while True:
            res = self.storage_server.get(uid)
            if res is None or res.startswith("[DATA]"):
                return uid
            elif res.startswith("[POINTER]"):
                uid = res[10:]
            else:
                raise IntegrityError()
        
    def upload(self, name, value):
        # Replace with your implementation
        uid = path_join(self.username, name)

        e_name = self.crypto.symmetric_encrypt(uid, self.crypto.cryptographic_hash(str(self.elg_priv_key.x), 'SHA256'), 'AES', 'CTR', counter = self.crypto.new_counter(128))

        e_value = self.crypto.symmetric_encrypt(value, self.crypto.cryptographic_hash(str(self.elg_priv_key.x), 'SHA256'), 'AES', 'CTR', counter = self.crypto.new_counter(128))

        rsa_key = RSA_to_json_string(self.rsa_priv_key)
        
        # should we add [DATA] pointers and then encrypt them?

        mac = self.crypto.message_authentication_code(e_value, self.crypto.cryptographic_hash(str(rsa_key), 'SHA256'), 'SHA256')

        mac_and_val = path_join(mac, e_value)
        self.storage_server.put(e_name, mac_and_val)

    def download(self, name):
        # Replace with your implementation
        uid = path_join(self.username, name)
        e_name = self.crypto.symmetric_encrypt(uid, self.crypto.cryptographic_hash(str(self.elg_priv_key.x), 'SHA256'), 'AES', 'CTR', counter = self.crypto.new_counter(128))

        stored_val = self.storage_server.get(e_name)
        if stored_val is None:
            return None

        if '/' not in stored_val:
            raise IntegrityError()
        mac_enc_val, enc_val = stored_val.split('/')

        rsa_key = RSA_to_json_string(self.rsa_priv_key)

        mac = self.crypto.message_authentication_code(enc_val, self.crypto.cryptographic_hash(str(rsa_key), 'SHA256'), 'SHA256')

        if mac_enc_val != mac:
            raise IntegrityError()
        return self.crypto.symmetric_decrypt(enc_val, self.crypto.cryptographic_hash(str(self.elg_priv_key.x), 'SHA256'), 'AES', 'CTR', counter = self.crypto.new_counter(128))


    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        


   def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
