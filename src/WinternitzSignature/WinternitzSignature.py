from src.base.BaseAlgorithm import BaseSignature, KeyPair, Key, Signature

from math import log2

from typing import TYPE_CHECKING, Union, Any
if TYPE_CHECKING:
    from src.base.TaggedValue import TaggedValue

class WinternitzSignature(BaseSignature):
    """
    Winternitz signature algorithm.

    For algorithm description, see here:
    https://kryptocheck.cz/podpisy-zalozene-na-hashich-iii-uvod-do-winternitzova-jednorazoveho-podpisu/
    https://kryptocheck.cz/podpisy-zalozene-na-hashich-iv-winternitzuv-podpisovy-algoritmus/

    FOR EDUCATIONAL PURPOSES ONLY, DO NOT USE IN PRODUCTION.

    """

    CLASS_NAME = "Winternitz"

    def __init__(self,
                 hash_name: str | None = None,
                 truncate_to_bytes: int | None = None,
                 w: int = 256
                 ) -> None:
        """
        Initialization of instance of this algorithm.

        Args:
            hash_name: name of hash algorithm that will be used
            truncate_to_bytes: Should hash output be truncated? if None, full length of hash output will be used
            w: Winternitz parameter. ln(w) says how many bit are processed at once.

        """

        super().__init__(hash_name, truncate_to_bytes)
        self.w = w

        # l1 - length of first part of signature (how many parts is signature hash break into)
        # l2 - length of second part of signature (checksum validation)
        self._l1 = int(((self._hash_length_bytes * 8 - 1) // log2(self.w)) + 1)
        self._l2 = int((log2(self._l1 * (self.w - 1)) // log2(self.w)) + 1)

        # maximum possible sum of all l1 values
        self.max_sum = (self.w - 1) * self._l1

    def export_data(self
                    ) -> dict[str, Any]:
        """
        Exports class data into dict.

        Returns:
            Dict with class data

        """
        data = super().export_data()
        data["w"] = self.w

        return data

    def generate_keypair(self
                         ) -> "WinternitzKeyPair":
        """
        Generates keypair for this algorithm and returns it.

        Returns:
            Generated keypair
        """

        keypair = WinternitzKeyPair(self._hash_name, truncate_to_bytes=self._hash_length_bytes, w=self.w)
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

        message_hash_list = message_hash.to_base(self.w, self._l1)

        checksum = self.max_sum - sum(message_hash_list)

        checksum_list = self.convert_integer_to_base(checksum, self.w, self._l2)

        for index, i in enumerate(message_hash_list + checksum_list):
            signature_data.append(self.compute_hashchain(private_key.value[index].copy(), i))

        params_dict = {"algorithm": self._hash_name,
                       "hash_length_bytes": self._hash_length_bytes,
                       "w": self.w}

        return Signature(signed_hash = message_hash,
                         signature = signature_data,
                         algorithm = self.CLASS_NAME,
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

        message_hash_list = message_hash.to_base(self.w,self._l1)

        checksum = self.max_sum - sum(message_hash_list)

        checksum_list = self.convert_integer_to_base(checksum, self.w, self._l2)

        correct = True
        for index, i in enumerate(message_hash_list + checksum_list):
            signature_candidate = self.compute_hashchain(signature_data[index].copy(), self.w - 1 - i)
            if signature_candidate != public_key.value[index]:
                correct = False

        return correct

    def _verify_signature(self,
                          signature: Union ["Signature", list[bytes]]
                          ) -> bool:
        """
        Verifies that given Signature value is actually valid signature for this algorithm.

        VERIFIES ONLY STRUCTURE OF SIGNATURE, not signature itself.

        Args:
            signature:
                either Signature class or just list of bytes representing Naive signature of compatible
                parameters

        Returns:
            Result of verification

        """

        if isinstance(signature, Signature):
            signature_data = signature.signature
        else:
            signature_data = signature

        if len(signature_data) != self._l1 + self._l2:
            return False

        for s in signature_data:
            if len(s) != self._hash_length_bytes:
                return False

        return True

class WinternitzKeyPair(KeyPair):
    """
    Class for Winternitz signature algorithm keypair.

    For algorithm description, see here:
    https://kryptocheck.cz/podpisy-zalozene-na-hashich-iii-uvod-do-winternitzova-jednorazoveho-podpisu/
    https://kryptocheck.cz/podpisy-zalozene-na-hashich-iv-winternitzuv-podpisovy-algoritmus/

    """

    CLASS_NAME = "Winternitz"

    def __init__(self,
                 hash_name: str | None = None,
                 truncate_to_bytes: int | None = None,
                 w: int = 256
                 ) -> None:
        super().__init__(hash_name, truncate_to_bytes)
        self.w = w

        # l1 - length of first part of signature (how many parts is signature hash break into)
        # l2 - length of second part of signature (checksum validation)
        self._l1 = int(((self._hash_length_bytes * 8 - 1) // log2(self.w)) + 1)
        self._l2 = int((log2(self._l1 * (self.w - 1)) // log2(self.w)) + 1)

    def export_data(self
                    ) -> dict[str, Any]:
        """
        Exports class data into dict.

        Returns:
            Dict with class data

        """
        data = super().export_data()
        data["w"] = self.w

        return data

    def generate_keypair(self
                         ) -> None:
        """
        Generates private key as a list of length given by values l1 + l2, based on hash length and parameter w.
        Each value is of length given by used hash.

        E.g. for 256-bit hash and w=256 generates 34 values of length 256(bits) as private key.

        Also generates public key by independently hashing each private key value.

        """

        private_key_value = []
        public_key_value = []

        for _ in range(self._l1 +self._l2):
            key_value = self.generate_random(self._hash_length_bytes)
            private_key_value.append(key_value)
            public_key_value.append(self.compute_hashchain(key_value.copy(), self.w - 1))

        params_dict = {"algorithm": self._hash_name,
                       "hash_length_bytes": self._hash_length_bytes,
                       "w": self.w}

        self.private_key = Key(is_private=True,
                               algorithm=self.CLASS_NAME,
                               params=params_dict,
                               value=private_key_value)

        self.public_key = Key(is_private=False,
                              algorithm=self.CLASS_NAME,
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

        if private_key.algorithm != "Winternitz":
            return False

        if len(private_key.value) != self._l1 + self._l2:
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

