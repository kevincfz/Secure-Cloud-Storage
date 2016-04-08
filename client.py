"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
from util import to_json_string
from util import from_json_string


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

        # get keys
        k_e = self.crypto.get_random_bytes(16)
        k_a = self.crypto.get_random_bytes(16)
        k_n = self.crypto.get_random_bytes(16)

        # Store the client's information node
        info = {}
        info["k_e"] = k_e
        info["k_a"] = k_a
        info["k_n"] = k_n
        info["files_I_shared"] = {}
        info["files_shared_to_me"] = {}

        self.info = info

        self.update_information(info)

    def upload(self, name, value):
        info = self.get_information()

        # files that own
        if name not in info["files_shared_to_me"]:
            k_e = info["k_e"]
            k_a = info["k_a"]
            k_n = info["k_n"]
            # files that own, and i have shared
            if name in info["files_I_shared"]:
                k_e = info["files_I_shared"][name]["shared_k_e"]
                k_a = info["files_I_shared"][name]["shared_k_a"]
                k_n = info["files_I_shared"][name]["shared_k_n"]

            name_key = name + k_n
            r = self.crypto.cryptographic_hash(name_key, hash_name='SHA256')
            user_name = self.username

        # files that i do not own, but shared to me
        else:
            secret = info["files_shared_to_me"][name]
            k_e = secret["shared_k_e"]
            k_a = secret["shared_k_a"]
            r = secret["r"]
            user_name = secret["from_username"]

        # use k_e to encrypt the file
        crypto_iv = self.crypto.get_random_bytes(16)
        encrypted_file = self.crypto.symmetric_encrypt(value, k_e,
                                                       cipher_name='AES',
                                                       mode_name='CBC',
                                                       iv=crypto_iv)

        cipher_text = to_json_string({"crypto_iv":  crypto_iv,
                                      "encrypted_file": encrypted_file})

        # use k_n to generate a confidential filename
        data_path = path_join(user_name, r)
        self.storage_server.put(data_path, cipher_text)

        # use k_a to generate a MAC code of cipher_text and name (to avoid CreateFakeKey)
        MAC_data = cipher_text + r
        MAC_tag = self.crypto.message_authentication_code(MAC_data,
                                                          k_a,
                                                          hash_name='SHA256')
        MAC_path = path_join(user_name, "metadata", r)
        self.storage_server.put(MAC_path, MAC_tag)

    def download(self, name):
        info = self.get_information()

        # files that own
        if name not in info["files_shared_to_me"]:
            k_e = info["k_e"]
            k_a = info["k_a"]
            k_n = info["k_n"]

            # files that own, and i have shared
            if name in info["files_I_shared"]:
                k_e = info["files_I_shared"][name]["shared_k_e"]
                k_a = info["files_I_shared"][name]["shared_k_a"]
                k_n = info["files_I_shared"][name]["shared_k_n"]

            name_key = name + k_n
            r = self.crypto.cryptographic_hash(name_key, hash_name='SHA256')
            user_name = self.username

        # files that i do not own, but shared to me
        else:
            secret = info["files_shared_to_me"][name]
            k_e = secret["shared_k_e"]
            k_a = secret["shared_k_a"]
            r = secret["r"]
            user_name = secret["from_username"]

        # Get the data using k_n
        data_path = path_join(user_name, r)
        cipher_text = self.storage_server.get(data_path)

        # Verify cipher_text if not none
        if cipher_text:
            MAC_data = cipher_text + r
            MAC_tag_computed = self.crypto.message_authentication_code(MAC_data, k_a, hash_name='SHA256')
            MAC_path = path_join(user_name, "metadata", r)
            MAC_tag = self.storage_server.get(MAC_path)

            if MAC_tag != MAC_tag_computed:
                raise IntegrityError("MACs do not match!")

            cipher_text_dict = from_json_string(cipher_text)
            downloaded_iv = cipher_text_dict["crypto_iv"]
            downloaded_file = cipher_text_dict["encrypted_file"]

            try:
                data = self.crypto.symmetric_decrypt(downloaded_file,
                                                     k_e,
                                                     cipher_name='AES',
                                                     mode_name='CBC',
                                                     iv=downloaded_iv)
                return data
            except ValueError:
                raise IntegrityError("Data compromised, possibly IV is messed up!")
        return None

    def share(self, user, name):
        info = self.get_information()
        link = self.crypto.get_random_bytes(16)


        # In this case, I do not own this file, this file is shared to me
        if name in info["files_shared_to_me"]:
            shared_k_a = info["files_shared_to_me"][name]["shared_k_a"]
            shared_k_e = info["files_shared_to_me"][name]["shared_k_e"]

        else:
            if name not in info["files_I_shared"]:
                shared_k_e = self.crypto.get_random_bytes(16)
                shared_k_a = self.crypto.get_random_bytes(16)
                shared_k_n = self.crypto.get_random_bytes(16)

                # Get a new name_key and new R, upload this to the new R
                name_key = name + shared_k_n
                r = self.crypto.cryptographic_hash(name_key, hash_name='SHA256')
                self.upload(name, self.download(name))

                info["files_I_shared"][name] = {
                    "users": [(user, link)],  # using list, maybe run time is slow when lookup?
                    "shared_k_e": shared_k_e,
                    "shared_k_a": shared_k_a,
                    "shared_k_n": shared_k_n,
                    "r": r
                }
            else:
                info["files_I_shared"][name]["users"].append((user, link))

            shared_k_e = info["files_I_shared"][name]["shared_k_n"]
            shared_k_a = info["files_I_shared"][name]["shared_k_a"]
            r = info["files_I_shared"][name]["r"]

            secret = {"r": r,
                      "shared_k_e": shared_k_e,
                      "shared_k_a": shared_k_a,
                      "from_username": self.username}
            secret_string = to_json_string(secret)
            encrypted_secret = self.crypto.asymmetric_encrypt(secret_string,
                                                              self.pks.get_public_key(user))
            self.storage_server.put(path_join(self.username, "shared", user, link),
                                    encrypted_secret)
            link_signature = self.crypto.asymmetric_sign(link, self.private_key)
            return link, link_signature

    def receive_share(self, from_username, newname, message):
        link = message[0]
        link_signature = message[1]
        verify = self.crypto.asymmetric_verify(link, link_signature, self.pks.get_public_key(from_username))
        if not verify:
            raise IntegrityError("Link is modified during transmission, don't click")
        encrypted_secret = self.storage_server.get(path_join(from_username, "shared", self.username, link))
        secret_string = self.crypto.asymmetric_decrypt(encrypted_secret, self.private_key)
        secret = from_json_string(secret_string)
        # secret["from_username"] = from_username
        info = self.get_information()
        info["files_shared_to_me"][newname] = secret

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        info = self.get_information()
        if name not in info["files_I_shared"]:
            return
        new_k_e = self.crypto.get_random_bytes(16)
        new_k_a = self.crypto.get_random_bytes(16)
        new_k_n = self.crypto.get_random_bytes(16)
        name_key = name + new_k_n
        r = self.crypto.cryptographic_hash(name_key, hash_name='SHA256')
        users = info["files_I_shared"][name]["users"]

        for person in users:
            if person[0] != user:
                secret = {"r": r,
                          "shared_k_e": new_k_e,
                          "shared_k_a": new_k_a}
                secret_string = to_json_string(secret)
                encrypted_secret = self.crypto.asymmetric_encrypt(secret_string,
                                                                  self.pks.get_public_key(person[0]))
                self.storage_server.put(path_join(self.username, "shared", person[0], person[1]),
                                        encrypted_secret)
            else:
                users.remove(person)

        info["files_I_shared"][name] = {
                    "users": users,  # using list, maybe run time is slow when lookup?
                    "shared_k_e": new_k_e,
                    "shared_k_a": new_k_a,
                    "shared_k_n": new_k_n,
                    "r": r
                }

        data = self.download(name)
        self.upload(name, data)

    def get_information(self):
        """
        :return: The decrypted dictionary stored at /information/<self.username>
        """
        username = self.username
        private_key = self.private_key

        info_path = path_join("information", username)
        signature_path = path_join("information", username, "signature")
        encrypted_information = self.storage_server.get(info_path)
        signature = self.storage_server.get(signature_path)

        verify = self.crypto.asymmetric_verify(encrypted_information, signature, private_key)
        if not verify:
            raise IntegrityError("Meta Information do not verify.")

        info_string = self.crypto.asymmetric_decrypt(encrypted_information, private_key)
        info = from_json_string(info_string)
        return info

    def update_information(self, new_info):
        """
        Encrypt and put on server the updated info, and update the signature as well.

        :param new_info: updated info, a dictionary
        :return: nothing
        """
        public_key = self.private_key.publickey()
        info_path = path_join("information", self.username)

        new_info_string = to_json_string(new_info)
        signature_path = path_join("information", self.username, "signature")

        encrypted_info = self.crypto.asymmetric_encrypt(new_info_string, public_key)
        encrypted_keys_signature = self.crypto.asymmetric_sign(encrypted_info,
                                                               self.private_key)

        self.storage_server.put(info_path, encrypted_info)
        self.storage_server.put(signature_path, encrypted_keys_signature)





