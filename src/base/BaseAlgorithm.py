from src.base.HBUtils import HBUtils
from src.base.TaggedValue import TaggedValue

from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import Self, Any, Union

class BaseSignature(HBUtils, ABC):
    """
    Base abstract class for Signatures.

    """

    CLASS_NAME = "Base"

    def __init__(self,
                 hash_name: str | None = None,
                 truncate_to_bytes: int | None = None
                 ) -> None:
        """
        Initialization of base class.

        Args:
            hash_name: name of hash algorithm that will be used
            truncate_to_bytes: Should hash output be truncated? if None, full length of hash output will be used

        """

        super().__init__(hash_name, truncate_to_bytes)

    @classmethod
    def load_data(cls,
                  data_dict: dict[str, Any]):
        """
        Loads class data from data_dict.


        Args:
            data_dict:
                Dict with class data

        Returns:
            new instance of this class loaded with given data

        """

        if "class_name" not in data_dict:
            raise ValueError("cannot instantiate class with this data_dict")

        if data_dict["class_name"] != cls.CLASS_NAME:
            raise ValueError("cannot instantiate class with this data_dict")

        del data_dict["class_name"]

        class_instance = cls(**data_dict)

        return class_instance


    @abstractmethod
    def generate_keypair(self
                         ) -> None:
        """
            Generates keypair for this algorithm and returns it.


            Returns:
                Generated keypair

        """

        pass

    @abstractmethod
    def sign(self,
             message: Union[str, bytes, "TaggedValue"],
             private_key: "Key",
             already_hashed : bool=False
             ) -> "Signature":
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

        pass

    @abstractmethod
    def verify(self,
               signature: "Signature",
               public_key: "Key",
               message: Union[str, bytes, "TaggedValue"],
               already_hashed: bool = False):
        """
        Verifies signature of given message and returns result of this verification. When already_hashed is set to True,
        it considers "message" to already be  hash-to-be-signed (for forging purposes), else (default) it considers it
        to be a message that shall be hashed first.


        Args:
            signature: Signature Class that contains signature data
            public_key: public key to validate signature with
            message: message that was signed
            already_hashed: Should message be hashed (False), or already signed (True)?

        Returns:
            result of validation

        """

        pass


class KeyPair(HBUtils, ABC):
    """
    Base abstract class for Keypair.

    """

    CLASS_NAME = "Base"

    def __init__(self,
                 hash_name: str | None = None,
                 truncate_to_bytes: int | None = None
                 ) -> None:
        """
            Initialization of Base keypair class.

            Args:
               hash_name: name of hash algorithm that will be used
               truncate_to_bytes: Should hash output be truncated? if None, full length of hash output will be used

        """

        super().__init__(hash_name, truncate_to_bytes)

        self.private_key: Key | None = None
        self.public_key: Key | None = None


    @abstractmethod
    def generate_keypair(self
                         ) -> None:
        """
        Generates private key and public key for given algorithm.

        """
        pass

    @abstractmethod
    def _validate_private_key(self,
                              private_key: "Key"
                              ) -> bool:
        """
        Validates that given private_key is valid for this signature algorithm and parameters.

        Args:
            private_key: private key to validate

        Returns:
            Result of validation

        """
        pass

    @abstractmethod
    def _validate_public_key(self,
                             public_key: "Key"
                             ) -> bool:
        """
        Validates that given public_key is valid for this signature algorithm and parameters.

        Args:
            public_key: public key to validate

        Returns:
            Result of validation

        """

        pass

    def export_data(self
                    ) -> dict[str, any]:
        """
        Exports data in python dict form.

        Returns:
            python dict with keypair data.

        """

        data = super().export_data()

        if self.private_key:
            data["private_key"] = self.private_key.export_data()

        if self.public_key:
            data["public_key"] = self.public_key.export_data()

        return data

    @classmethod
    def load_data(cls,
                  data_dict: dict[str, Any]):
        """
        Loads class data from data_dict.


        Args:
            data_dict:
                Dict with class data

        Returns:
            new instance of this class loaded with given data

        """

        if "class_name" not in data_dict:
            raise ValueError("cannot instantiate class with this data_dict")

        if data_dict["class_name"] != cls.CLASS_NAME:
            raise ValueError("cannot instantiate class with this data_dict")

        del data_dict["class_name"]

        if "private_key" in data_dict:
            private_key = Key(**data_dict["private_key"])
            del data_dict["private_key"]
        else:
            private_key = None

        if "public_key" in data_dict:
            public_key = Key(**data_dict["public_key"])
            del data_dict["public_key"]
        else:
            public_key = None

        class_instance = cls(**data_dict)

        if private_key:
            is_valid = class_instance._validate_private_key(private_key)
            if not is_valid:
                raise ValueError("Private key is not valid")
            class_instance.private_key = private_key

        if public_key:
            is_valid = class_instance._validate_public_key(public_key)
            if not is_valid:
                raise ValueError("Public key is not valid")
            class_instance.public_key = public_key

        return class_instance


@dataclass
class Key:
    """
    Simple dataclass for Key instances.

    Attributes:
        is_private: Is this private key (True) or public key (False)?
        algorithm: For what algorithm is this key meant?
        value: Value of this key
        params: Parameters dict for this key
        sibling_key: Optional reference to sibling (private -> public; public -> private) key.

    """

    is_private: bool
    algorithm: str
    value: Any
    params: dict[str, Any] | None = None
    sibling_key: Self | None = None

    def export_data(self
                    ) -> dict[str, Any]:
        """
         Exports data in python dict form.

         Returns:
             python dict with keypair data.

         """

        data = {"is_private": self.is_private,
                "algorithm": self.algorithm,
                "value": HBUtils.encode_value(self.value),
                "params": self.params}

        return data

    def __post_init__(self
                      ) -> None:
        """
        Automatically calls decode to relevant values after initialization.

        """

        self.value = HBUtils.decode_value(self.value)

@dataclass
class Signature:
    """
    Simple dataclass for Signature instances.

    Attributes:
        signed_hash: hash that was actually signed
        signature: signature value
        algorithm: For what algorithm is this key meant?
        params: Parameters dict for this key
        original_data: optional data that was signed

    """

    signed_hash: TaggedValue | bytes
    signature: Any
    algorithm: str
    params: dict[str, Any] | None = None
    original_data: str | None = None


    def __post_init__(self
                      ) -> None:
        """
        Automatically calls decode to relevant values after initialization.

        """

        self.signed_hash = HBUtils.decode_value(self.signed_hash)
        self.signature = HBUtils.decode_value(self.signature)
        self.original_data = HBUtils.decode_value(self.original_data)

    def export_data(self
                    ) -> dict[str, Any]:
        """
         Exports data in python dict form.

         Returns:
             python dict with keypair data.

         """

        data = {"signed_hash": HBUtils.encode_value(self.signed_hash),
                "signature": HBUtils.encode_value(self.signature),
                "algorithm": self.algorithm,
                "params": self.params,
                "original_data": HBUtils.encode_value(self.original_data)}

        return data

