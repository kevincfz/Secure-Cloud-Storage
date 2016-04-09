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
            from_origin = info["files_shared_to_me"][name][2]
            secret = self.get_linked_data(link, from_username, from_origin)
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
            from_origin = info["files_shared_to_me"][name][2]
            secret = self.get_linked_data(link, from_username, from_origin)
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
            from_origin = info["files_shared_to_me"][name][2]
            secret = self.get_linked_data(infolink, from_username, from_origin)
            k_e = secret["k_e"]
            k_a = secret["k_a"]
            r = secret["r"]
            username = secret["from_user"]
            self.update_children_directory(infolink, (user, link))
        else:
            return None

        secret = {"k_e": k_e,
                  "k_a": k_a,
                  "r": r,
                  "from_user": username}
        linked_data = self.generate_linked_data(secret, user)

        self.storage_server.put(path_join(user, "shared", link),
                                to_json_string(linked_data))
        msg = {}
        msg["link"] = link
        msg["origin"] = username
        msg_signature = self.crypto.asymmetric_sign(to_json_string(msg), self.private_key)
        return to_json_string(msg), msg_signature

    def receive_share(self, from_username, newname, message):
        if message is None:
            raise ValueError("You received empty message")
        msg_string, msg_signature = message
        verify = self.crypto.asymmetric_verify(msg_string, msg_signature, self.pks.get_public_key(from_username))
        if not verify:
            raise IntegrityError("Link is modified during transmission, don't click")

        msg = from_json_string(msg_string)
        link = msg["link"]
        origin = msg["origin"]

        # prepare a route for sharing shared files
        children_path = path_join(self.username, "shared", link, "children")
        children_data = {"children": []}
        children_signature = self.crypto.asymmetric_sign(to_json_string(children_data["children"]),
                                                         self.private_key)
        children_data["signature"] = children_signature
        self.storage_server.put(children_path, to_json_string(children_data))

        info = self.get_information()
        info["files_shared_to_me"][newname] = [link, from_username, origin]
        # So that we know where the link come from, so that we know whose public key we should use to verify
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
        rootchildren = info["files_I_own"][name]["users"]
        goodusers = []

        to_remove = []
        for rootchild in rootchildren:
            if rootchild[0] == user:
                to_remove.append(rootchild)
                break

        while to_remove:
            baduser = to_remove.pop()
            rootchildren.remove(baduser)

        goodusers.extend(rootchildren)
        more_children = self.get_all_descendant(rootchildren)
        goodusers.extend(more_children)

        for gooduser in goodusers:
            gooduser_name = gooduser[0]
            gooduser_link = gooduser[1]

            secret = {"k_e": new_k_e,
                      "k_a": new_k_a,
                      "r": r,
                      "from_user": self.username}

            linked_data = self.generate_linked_data(secret, gooduser_name)
            self.storage_server.put(path_join(gooduser_name, "shared", gooduser_link),
                                    to_json_string(linked_data))

        info["files_I_own"][name] = {
                    "users": rootchildren,
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

    def get_linked_data(self, link, link_fromuser, link_origin):
        """
        Get linked data, and validate its integrity,

        :param new_info: updated info, a dictionary
        :return: secret, only if the integrity is not violated
        """
        data_path = path_join(self.username, "shared", link)
        linked_data = self.storage_server.get(data_path)
        linked_data = from_json_string(linked_data)

        encrypted_secret = linked_data["encrypted_secret"]
        encrypted_key = linked_data["encrypted_key"]
        signature = linked_data["signature"]
        crypto_iv = linked_data["iv"]
        verify = self.crypto.asymmetric_verify(encrypted_secret + encrypted_key + crypto_iv, signature,
                                               self.pks.get_public_key(link_fromuser))
        verify_origin = self.crypto.asymmetric_verify(encrypted_secret + encrypted_key + crypto_iv, signature,
                                                      self.pks.get_public_key(link_origin))

        if not (verify or verify_origin):
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

    def get_all_descendant(self, rootchildren):
        from collections import deque
        """
        Get a all descendants of rootchildren, using BFS
        :param rootchildren:
        :return:
        """
        descendants = []
        children_queue = deque(rootchildren)
        while children_queue:
            child = children_queue.popleft()
            children = self.get_children(child[0], child[1])

            for c in children:
                descendants.append(c)
                # so we record all the children
                children_queue.append(c)
                # so we run the BFS
        return descendants

    def update_children_directory(self, link, user_to_share):
        """
        If I did not own this file, and I am sharing this file, I will
        call this function, to update /<my name>/shared/<link>/children,
        which stores { "children": [("child1", "child1 link"),
                                    ("child2", "child2 new link),
                      "signature" : Asymmetric_sign(children)}
        Use signature to defend against attack, which might replace info in children,
        once we revoke, someone who has no access might have access now.
        link and who's shared to dont have to be a secret
        :param link: the link that points to the secrets
        :param user_to_share
        :return:
        """
        children_path = path_join(self.username, "shared", link, "children")
        children_data = self.storage_server.get(children_path)
        children_data = from_json_string(children_data)
        children = children_data["children"]
        signature = children_data["signature"]
        verify = self.crypto.asymmetric_verify(to_json_string(children),
                                               signature,
                                               self.pks.get_public_key(self.username))
        if not verify:
            raise IntegrityError("When I am updating children directory, data has been compromised.")

        children.append(user_to_share)
        new_signature = self.crypto.asymmetric_sign(to_json_string(children), self.private_key)
        children_data["children"] = children
        children_data["signature"] = new_signature
        self.storage_server.put(children_path, to_json_string(children_data))

    def get_children(self, user_name, link):
        """
        Return a list of children of user_name, each child is [name, link]
        :param link:
        :param user_name
        :return:
        """
        children_data = self.storage_server.get(path_join(user_name, "shared", link, "children"))
        children_data = from_json_string(children_data)
        children = children_data["children"]
        signature = children_data["signature"]
        verify = self.crypto.asymmetric_verify(to_json_string(children),
                                               signature,
                                               self.pks.get_public_key(user_name))
        if not verify:
            raise IntegrityError("Children Data has been compromised!")
        return children
