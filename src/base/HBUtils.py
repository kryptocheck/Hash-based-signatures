import random
import hashlib

from typing import Any

from src.base.TaggedValue import TaggedValue

class HBUtils:
    """
    Base class that handles stuff that both algorithm and keypair classes needs.

    """

    CLASS_NAME: str = "Default"
    DEFAULT_HASH: str = "sha-256"

    def __init__(self,
                 hash_name: str = None,
                 truncate_to_bytes: int = None
                 ) -> None:
        """
        Initialize class. Loads hash algorithm to use.

        Args:
            hash_name: name of hash algorithm that will be used
            truncate_to_bytes: Should hash output be truncated? if None, full length of hash output will be used
        """

        self._hash_name: str = hash_name
        self._hash_length_bytes: int

        if not self._hash_name:
            self.hash_name = self.DEFAULT_HASH

        self._hash_length_bytes, self._hash_function = self._load_hash_function()

        if truncate_to_bytes and truncate_to_bytes < self._hash_length_bytes:
            self._hash_length_bytes = truncate_to_bytes

    def _load_hash_function(self
                            ) -> tuple[int, callable]:
        """
        Try to load hash algorithm based on hash_name.

        Returns:
            tuple: byte length of output, callable hash algorithm

        Raises:
            NotImplementedError: Unsupported hash name is being loaded

        """

        match self._hash_name.lower():
            case "sha256" | "sha-256":
                return 32, hashlib.sha256
            case _ :
                raise NotImplementedError(f"hash function {self.hash_name} not supported")

    def compute_hash(self,
                     hash_input: TaggedValue | bytes
                     ) -> TaggedValue:
        """
        Computes actual hash using preloaded algorithm and truncates result to expected length.
        Creates TaggedValue class for result if necessary.


        Args:
            hash_input: Can be either bytes or TaggedValue class.

        Returns:
            result in format of TaggedValue

        """

        if isinstance(hash_input, TaggedValue):
            new_hash = self._hash_function(hash_input.value)
            new_digest = new_hash.digest()[:self._hash_length_bytes]
            hash_input.update_value(new_digest)
            return hash_input
        else:
            value = self._hash_function(hash_input).digest()
            new_digest = value[:self._hash_length_bytes]
            tagged = TaggedValue(new_digest)
            return tagged

    @staticmethod
    def generate_random(bytes_needed: int
                        ) -> TaggedValue:
        """
        Generates bytes of given length and returns in format of TaggedValue.

        Args:
            bytes_needed: needed length in bytes

        Returns:
            Random bytes in TaggedValue form

        """

        if not isinstance(bytes_needed, int):
            raise ValueError(f"Expected integer, got {bytes_needed}")

        if bytes_needed < 0:
            raise ValueError(f"Number of bytes cannot be negative: {bytes_needed}")

        value = random.randbytes(bytes_needed)
        tagged = TaggedValue(value)

        return tagged

    def export_data(self
                    ) -> dict[str, Any]:
        """
        Exports class data into dict.

        Returns:
            Dict with class data

        """
        data = {"hash_name": self._hash_name,
                "truncate_to_bytes": self._hash_length_bytes,
                "class_name": self.CLASS_NAME}

        return data

    @staticmethod
    def encode_value(value: Any
                     ) -> Any:
        """
        Encodes value into representation that can be saved into json. Calls itself recursively for list/dict purposes.

        Args:
            value:
                value to encode

        Returns:
            Encoded value

        """
        match value:
            case str() |  int():
                return value

            case bytes():
                return value.hex()

            case TaggedValue():
                return value.value.hex()

            case list():
                result = []
                for x in value:
                    result.append(HBUtils.encode_value(x))

                return result

            case dict():
                result = {}
                for x in value:
                    result[x] = HBUtils.encode_value(value[x])

                return result

            case _ :
                raise NotImplementedError(f"Unsupported type: {type(value)}")

    @staticmethod
    def decode_value(value: Any
                     ) -> Any:
        """
        Counterpart to encode value, decodes value from json representation into relevant form, when appropriate.
        Calls itself recursively for list/dict purposes.

        Args:
            value:
                value to decode

        Returns:
            decoded value

        """
        match value:
            case int() | bytes() | TaggedValue():
                return value

            case str():
                return TaggedValue(bytes.fromhex(value))

            case list():
                result = []
                for x in value:
                    result.append(HBUtils.decode_value(x))

                return result

            case dict():
                result = {}
                for x in value:
                    result[x] = HBUtils.decode_value(value[x])

                return result

            case _:
                raise NotImplementedError(f"Unsupported type: {type(value)}")


    @staticmethod
    def get_minimums_in_lists(lists: list[list[int]]
                              ) -> tuple[list[int], list[int]]:
        """
        Takes an arbitrary number of lists (in form of list of lists) of same length containing numbers and
        for each position finds minimum and index of list where that minimum was hit. For index of list to change
        there need to be new value LOWER than current one (ties go to first list where given number was found).

        Args:
            lists: List of lists of integers to compare

        Returns:
            2 value tuple - list of minimums and list containing indexes in which list was that minimum found.

        Examples:
            [[0,1,3,2],[3,6,1,2]] -> ([0,1,1,2],[0,0,1,0])
            [[0,1,2,3],[0,1,2,3],[0,1,2,3]] -> ([0,1,2,3],[0,0,0,0])
        """
        if not lists:
            return [], []

        l_len = len(lists[0])
        for l in lists:
            if len(l) != l_len:
                raise AttributeError(f"Can only compare lists of same length")

        minimums = [10**100] * l_len
        min_positions = [l_len] * l_len

        for list_index, l in enumerate(lists):
            for index, value in enumerate(l):
                if value < minimums[index]:
                    minimums[index] = value
                    min_positions[index] = list_index

        return minimums, min_positions

