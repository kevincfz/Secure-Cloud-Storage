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
        info_path = path_join("information", username)
        if not self.storage_server.get(info_path):

            # Store the client's information node
            info = {}
            info["files_I_own"] = {}
            info["files_shared_to_me"] = {}

            self.update_information(info)

    def upload(self, name, value):

        info = self.get_information()

        if name in info["files_I_own"]:
            k_e = info["files_I_own"][name]["k_e"]
            k_a = info["files_I_own"][name]["k_a"]
            r = info["files_I_own"][name]["r"]
            username = self.username

        elif name in info["files_shared_to_me"]:
            link = info["files_shared_to_me"][name][0]
            from_username = info["files_shared_to_me"][name][1]
            secret = self.get_linked_data(link, from_username)
            k_e = secret["k_e"]
            k_a = secret["k_a"]
            r = secret["r"]
            username = secret["from_user"]
        else:
            # first time uploading a file
            k_e = self.crypto.get_random_bytes(16)
            k_a = self.crypto.get_random_bytes(16)
            k_n = self.crypto.get_random_bytes(16)
            name_key = name + k_n
            r = self.crypto.cryptographic_hash(name_key, hash_name='SHA256')
            username = self.username
            info["files_I_own"][name] = {}
            info["files_I_own"][name]["k_e"] = k_e
            info["files_I_own"][name]["k_a"] = k_a
            info["files_I_own"][name]["r"] = r
            info["files_I_own"][name]["users"] = []
            self.update_information(info)

        # use k_e to encrypt the file
        crypto_iv = self.crypto.get_random_bytes(16)
        encrypted_file = self.crypto.symmetric_encrypt(value, k_e,
                                                       cipher_name='AES',
                                                       mode_name='CBC',
                                                       iv=crypto_iv)

        cipher_text = to_json_string({"crypto_iv":  crypto_iv,
                                      "encrypted_file": encrypted_file})

        data_path = path_join(username, r)
        self.storage_server.put(data_path, cipher_text)

        MAC_data = cipher_text + r
        MAC_tag = self.crypto.message_authentication_code(MAC_data,
                                                          k_a,
                                                          hash_name='SHA256')
        MAC_path = path_join(username, "metadata", r)
        self.storage_server.put(MAC_path, MAC_tag)

    def download(self, name):
        info = self.get_information()

        if name in info["files_I_own"]:
            k_e = info["files_I_own"][name]["k_e"]
            k_a = info["files_I_own"][name]["k_a"]
            r = info["files_I_own"][name]["r"]
            username = self.username

        elif name in info["files_shared_to_me"]:
            link = info["files_shared_to_me"][name][0]
            from_username = info["files_shared_to_me"][name][1]
            secret = self.get_linked_data(link, from_username)
            k_e = secret["k_e"]
            k_a = secret["k_a"]
            r = secret["r"]
            username = secret["from_user"]
        else:
            return None

        # Get the data using k_n
        data_path = path_join(username, r)
        cipher_text = self.storage_server.get(data_path)

        # Verify cipher_text if not none
        if cipher_text:
            MAC_data = cipher_text + r
            MAC_tag_computed = self.crypto.message_authentication_code(MAC_data, 
                                                                       k_a, 
                                                                       hash_name='SHA256')
            MAC_path = path_join(username, "metadata", r)
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

        if name in info["files_I_own"]:
            k_e = info["files_I_own"][name]["k_e"]
            k_a = info["files_I_own"][name]["k_a"]
            r = info["files_I_own"][name]["r"]
            username = self.username
            if user not in [tuple[0] for tuple in info["files_I_own"][name]["users"]]:
                info["files_I_own"][name]["users"].append((user, link))
            else:
                raise ValueError("You have already shared this file to this person.")
            self.update_information(info)

        elif name in info["files_shared_to_me"]:
            infolink = info["files_shared_to_me"][name][0]
            from_username = info["files_shared_to_me"][name][1]
            secret = self.get_linked_data(infolink, from_username)
            k_e = secret["k_e"]
            k_a = secret["k_a"]
            r = secret["r"]
            username = secret["from_user"]

        else:
            return None

        secret = {"k_e": k_e,
                  "k_a": k_a,
                  "r": r,
                  "from_user": username}
        linked_data = self.generate_linked_data(secret, user)

        self.storage_server.put(path_join(user, "shared", link),
                                to_json_string(linked_data))
        signed_link = self.crypto.asymmetric_sign(link, self.private_key)
        return link, signed_link

    def receive_share(self, from_username, newname, message):
        if message is None:
            raise ValueError("You received empty message")
        link = message[0]
        link_signature = message[1]
        verify = self.crypto.asymmetric_verify(link, link_signature, self.pks.get_public_key(from_username))
        if not verify:
            raise IntegrityError("Link is modified during transmission, don't click")

        info = self.get_information()
        info["files_shared_to_me"][newname] = (link, from_username)
                                                     # So that we know where the link come from,
                                                     # so that we know whose public key we should use to verify
        self.update_information(info)

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        info = self.get_information()
        if name not in info["files_I_own"]:
            return
        new_k_e = self.crypto.get_random_bytes(16)
        new_k_a = self.crypto.get_random_bytes(16)
        new_k_n = self.crypto.get_random_bytes(16)
        name_key = name + new_k_n
        r = self.crypto.cryptographic_hash(name_key, hash_name='SHA256')
        users = info["files_I_own"][name]["users"]

        to_remove = []

        for person in users:
            if person[0] != user:
                gooduser = person[0]
                gooduser_link = person[1]

                secret = {"k_e": new_k_e,
                          "k_a": new_k_a,
                          "r": r,
                          "from_user": self.username}

                linked_data = self.generate_linked_data(secret, gooduser)
                self.storage_server.put(path_join(gooduser, "shared", gooduser_link),
                                        to_json_string(linked_data))

            else:
                to_remove.append(person)

        while to_remove:
            person = to_remove.pop()
            users.remove(person)

        info["files_I_own"][name] = {
                    "users": users,  # using list, maybe run time is slow when lookup?
                    "k_e": new_k_e,
                    "k_a": new_k_a,
                    "r": r
                }

        data = self.download(name)
        self.update_information(info)
        self.upload(name, data)

    def update_information(self, new_info):
        """
        Encrypt and put on server the updated info, and update the signature as well.

        :param new_info: updated info, a dictionary
        :return: nothing
        """
        symmetric_key = self.crypto.get_random_bytes(16)
        public_key = self.private_key.publickey()
        info_path = path_join("information", self.username)

        new_info_string = to_json_string(new_info)
        signature_path = path_join("information", self.username, "signature")

        crypto_iv = self.crypto.get_random_bytes(16)
        encrypted_info = self.crypto.symmetric_encrypt(new_info_string, symmetric_key,
                                                       cipher_name='AES',
                                                       mode_name='CBC',
                                                       iv=crypto_iv)
        encrypted_k = self.crypto.asymmetric_encrypt(symmetric_key, public_key)

        cipher_text = to_json_string({"encrypted_k": encrypted_k,
                                      "crypto_iv":  crypto_iv,
                                      "encrypted_info": encrypted_info})

        info_signature = self.crypto.asymmetric_sign(cipher_text, self.private_key)

        self.storage_server.put(info_path, cipher_text)
        self.storage_server.put(signature_path, info_signature)

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

        encrypted_info = from_json_string(encrypted_information)
        k = self.crypto.asymmetric_decrypt(encrypted_info["encrypted_k"], private_key)
        iv = encrypted_info["crypto_iv"]
        data = encrypted_info["encrypted_info"]
        try:
            info = self.crypto.symmetric_decrypt(data,
                                                 k,
                                                 cipher_name='AES',
                                                 mode_name='CBC',
                                                 iv=iv)
            return from_json_string(info)
        except ValueError:
            raise IntegrityError("symmetric decryption failed during getting meta-info about a user, IV?")

    def generate_linked_data(self, secret, target_user):
        """
        Generate linked data

        :param
        :return linked_data
        """
        crypto_iv = self.crypto.get_random_bytes(16)
        symmetric_key = self.crypto.get_random_bytes(16)

        encrypted_secret = self.crypto.symmetric_encrypt(to_json_string(secret), symmetric_key,
                                                         cipher_name='AES',
                                                         mode_name="CBC",
                                                         iv=crypto_iv)
        encrypted_key = self.crypto.asymmetric_encrypt(symmetric_key, self.pks.get_public_key(target_user))
        signature = self.crypto.asymmetric_sign(encrypted_secret + encrypted_key + crypto_iv, self.private_key)
        linked_data = {"encrypted_secret": encrypted_secret,
                       "encrypted_key": encrypted_key,
                       "iv": crypto_iv,
                       "signature": signature}

        return linked_data


    def get_linked_data(self, link, link_fromuser):
        """
        Get linked data, and validate its integrity,

        :param new_info: updated info, a dictionary
        :return: secret, only if the integrity is not violated
        """

        linked_data = self.storage_server.get(path_join(self.username, "shared", link))
        linked_data = from_json_string(linked_data)

        encrypted_secret = linked_data["encrypted_secret"]
        encrypted_key = linked_data["encrypted_key"]
        signature = linked_data["signature"]
        crypto_iv = linked_data["iv"]
        verify = self.crypto.asymmetric_verify(encrypted_secret + encrypted_key + crypto_iv, signature,
                                               self.pks.get_public_key(link_fromuser))
        if not verify:
            raise IntegrityError("linked data has been compromised")

        symmetric_key = self.crypto.asymmetric_decrypt(encrypted_key, self.private_key)
        try:
            secret = from_json_string(self.crypto.symmetric_decrypt(encrypted_secret,
                                                                    symmetric_key,
                                                                    cipher_name='AES',
                                                                    mode_name='CBC',
                                                                    iv=crypto_iv))
            return secret
        except ValueError:
            raise IntegrityError("symmetric decryption failed during getting linked data, IV messed up?")


