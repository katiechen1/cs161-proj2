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

    def upload(self, name, value):
        # Replace with your implementation
        sym_enc_key = self.crypto.get_random_bytes(16)
        sym_mac_key = self.crypto.get_random_bytes(16)
        sym_conf_key = self.crypto.get_random_bytes(16)
        keys = path_join(sym_enc_key, sym_mac_key, sym_conf_key)

        # encryting the keys with elgamal private key
        enc_keys_elg = self.crypto.symmetric_encrypt(keys, self.crypto.cryptographic_hash(str(self.elg_priv_key.x), 'SHA256'), 'AES', 'CBC', self.crypto.get_random_bytes(16))
        # signing the encrypted keys with rsa private key
        rsa_key = RSA_to_json_string(self.rsa_priv_key)
        signed_encryted_keys = self.crypto.message_authentication_code(enc_keys_elg, self.crypto.cryptographic_hash(str(rsa_key), 'SHA256'), 'SHA256')
        # creating "signed(enc_keys) / enc_keys"
        mac_enc_cipher = path_join(signed_encryted_keys, enc_keys_elg)
        uid_and_dir = path_join(self.username, 'key_dir')
        # putting key node in server 
        self.storage_server.put(uid_and_dir, mac_enc_cipher)

        # encryting the file with sym_enc_key that we generated
        enc_contents = self.crypto.symmetric_encrypt(value, sym_enc_key, 'AES', 'CBC', self.crypto.get_random_bytes(16))
        #  creating "enc_contents/filename" for MAC
        cipher_filename = path_join(enc_contents, name)
        #macing the cipher_filename with sym_conf_key we generated
        mac_for_c_fname = self.crypto.message_authentication_code(cipher_filename, sym_conf_key, 'SHA256')
        #hashing filename
        hash_filename = self.crypto.cryptographic_hash(name, 'SHA256')
        # creating username/hash(filename)
        uid_fname = path_join(self.username, hash_filename)
        # put [ username/hash(filename) , mac(encfile || filename) ] into server DATANODE
        self.storage_server.put(uid_fname, mac_for_c_fname)

    def download(self, name):
        # Replace with your implementation
        enc_keys = path_join(self.username, 'key_dir')
       
        value = self.storage_server.get(enc_keys)
        if value is None:
            return None
        if '/' not in value:
            raise IntegrityError
        
        tocheck, cipher = value.split('/')
        rsa_key = RSA_to_json_string(self.rsa_priv_key)
        checksum = self.crypto.message_authentication_code(cipher, self.crypto.cryptographic_hash(str(rsa_key), 'SHA256'), 'SHA256')
        # check signature
        if tocheck != checksum:
            raise IntegrityError 
        #now decrypt to get the keys
        try:
            keys = self.crypto.symmetric_decrypt(cipher, self.crypto.cryptographic_hash(str(self.elg_priv_key.x), 'SHA256'), 'AES', 'CBC', self.crypto.get_random_bytes(16))
        except ValueError:
            print('idk')
            raise IntegrityError

        
        sym_enc_key, sym_mac_key, sym_conf_key = keys.split('/')
        
        uid = path_join(self.username, self.crypto.cryptographic_hash(name, 'SHA256'))
        #getting the encrypted value
        fileval = self.storage_server.get(uid)
        if fileval is None:
            return None
        if '/' not in fileval:
            return IntegrityError
        #checking the mac
        file_cipher, tocheck_mac = fileval.split('/')
        c_and_filename = path_join(file_cipher, name)
        checksum_mac = self.crypto.message_authentication_code(c_and_filename, sym_conf_key, 'SHA256')
        if checksum_mac != tocheck_mac:
            return IntegrityError
        return self.crypto.symmetric_decrypt(file_cipher, sym_enc_key, 'SHA256', 'AES', 'CBC', self.crypto.get_random_bytes(16))

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
