from src.base.BaseAlgorithm import BaseSignature, KeyPair, Key, Signature

from typing import TYPE_CHECKING, Union
if TYPE_CHECKING:
    from src.base.TaggedValue import TaggedValue

class NaiveSignature(BaseSignature):
    """
    Naive signature algorithm.

    For algorithm description, see here:
    https://kryptocheck.cz/podpisy-zalozene-na-hashich-i-zakladni-podpisovy-algoritmus/

    THIS ALGORITHM IS NOT SECURE AND IT IS HERE ONLY TO SHOW BASIS ON WHAT NEXT ALGORITHM BUILT.

    FOR EDUCATIONAL PURPOSES ONLY, DO NOT USE IN PRODUCTION.

    """

    CLASS_NAME = "Naive"

    def __init__(self,
                 hash_name: str | None = None,
                 truncate_to_bytes: int | None = None
                 ) -> None:
        """
        Initialization of instance of this algorithm.

        Args:
            hash_name: name of hash algorithm that will be used
            truncate_to_bytes: Should hash output be truncated? if None, full length of hash output will be used

        """

        super().__init__(hash_name, truncate_to_bytes)

    def generate_keypair(self
                         ) -> "NaiveKeyPair":
        """
        Generates keypair for this algorithm and returns it.


        Returns:
            Generated keypair
        """

        keypair = NaiveKeyPair(self._hash_name, truncate_to_bytes=self._hash_length_bytes)
        keypair.generate_keypair()

        return keypair

    def sign(self,
             message: Union[str, bytes, "TaggedValue"],
             private_key: Key,
             already_hashed : bool=False
             ) -> Signature:
        """
        Generates signature for this algorithm. When already_hashed is set to True, it considers "message" to already be
        hash-to-be-signed (for forging purposes), else (default) it considers it to be a message that shall be hashed
        first.

        Args:
            message: message to be signed
            private_key: private key that shall be used for signature
            already_hashed: Should message be hashed (False), or already signed (True)?

        Returns:
            Signature class containing created signature, message and signed hash.
        """

        signature_data = []

        if already_hashed:
            message_hash = message
        else:
            message_hash = self.compute_hash(message)

        message_hash_list = message_hash.to_base(2)

        for m_index, m in enumerate(message_hash_list):
            signature_bit = private_key.value[m_index].copy()
            if m == 1:
                signature_bit = self.compute_hash(signature_bit)
            signature_data.append(signature_bit)

        params_dict = {"_hash_name": self._hash_name,
                       "_hash_length_bytes": self._hash_length_bytes}

        return Signature(signed_hash = message_hash,
                         signature = signature_data,
                         algorithm = "Naive",
                         params = params_dict,
                         original_data = None if already_hashed else message)


    def verify(self,
               signature: Signature | list["TaggedValue"],
               public_key: Key,
               message: Union[str, bytes, "TaggedValue"],
               already_hashed: bool = False):
        """
        Verifies signature of given message and returns result of this verification. When already_hashed is set to True,
        it considers "message" to already be  hash-to-be-signed (for forging purposes), else (default) it considers it
        to be a message that shall be hashed first.


        Args:
            signature: Signature Class that contains signature data. Alternatively just list of TaggedValues without
                        that Signature class wrapper
            public_key: public key to validate signature with
            message: message that was signed
            already_hashed: Should message be hashed (False), or already signed (True)?

        Returns:
            result of validation

        """


        if already_hashed:
            message_hash = message
        else:
            message_hash = self.compute_hash(message)

        verification_list = []

        if isinstance(signature, Signature):
            signature_data = signature.signature
        else:
            signature_data = signature

        message_hash_list = message_hash.to_base(2)

        for m_index, m in enumerate(message_hash_list):
            signature_part = signature_data[m_index].copy()
            if m  == 0:
                signature_part = self.compute_hash(signature_part)
            verification_list.append(signature_part)

        correct = True
        for i in range(self._hash_length_bytes*8):
            if public_key.value[i] != verification_list[i]:
                correct = False

        return correct

class NaiveKeyPair(KeyPair):
    """
    Class for Naive signature algorithm keypair.

    For algorithm description, see here:
    https://kryptocheck.cz/podpisy-zalozene-na-hashich-i-zakladni-podpisovy-algoritmus/

    """

    CLASS_NAME = "Naive"

    def __init__(self,
                 hash_name: str | None = None,
                 truncate_to_bytes: int | None = None
                 ) -> None:
        super().__init__(hash_name, truncate_to_bytes)

    def generate_keypair(self
                         ) -> None:
        """
        Generates private key  as a list of length given by used hash - 1 for each bit of output.
        Each value is of length given by used hash.

        E.g. for 256-bit hash generates 256 values of length 256(bits) as private key.

        Also generates public key by independently hashing each private key value.

        """

        private_key_value = []
        public_key_value = []

        for _ in range(self._hash_length_bytes*8):
            key_value = self.generate_random(self._hash_length_bytes)
            private_key_value.append(key_value)
            public_key_value.append(self.compute_hash(key_value.copy()))

        params_dict = {"algorithm": self._hash_name,
                       "hash_length_bytes": self._hash_length_bytes}

        self.private_key = Key(is_private=True,
                               algorithm="Naive",
                               params=params_dict,
                               value=private_key_value)

        self.public_key = Key(is_private=False,
                              algorithm="Naive",
                              value=public_key_value,
                              params=params_dict,
                              sibling_key=self.private_key)

        self.private_key.sibling_key = self.public_key

    def _validate_private_key(self,
                              private_key: Key,
                              validating_public_key: bool=False
                              ) -> bool:
        """
        Validates that given private_key is valid for this signature algorithm and parameters.

        Args:
            private_key: private key to validate

        Returns:
            Result of validation

        """
        if not isinstance(private_key, Key):
            return False

        if private_key.is_private + validating_public_key != 1:
            return False

        if private_key.algorithm != "Naive":
            return False

        if len(private_key.value) != self._hash_length_bytes * 8:
            return False

        for i in private_key.value:
            if len(i) != self._hash_length_bytes:
                return False

        if private_key.params["hash_length_bytes"] != self._hash_length_bytes:
            return False

        return True

    def _validate_public_key(self,
                             public_key: Key
                             ) -> bool:
        """
        Validates that given public_key is valid for this signature algorithm and parameters.

        Args:
            public_key: private key to validate

        Returns:
            Result of validation

        """

        return self._validate_private_key(public_key, True)

