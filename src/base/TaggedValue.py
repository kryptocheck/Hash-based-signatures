from typing import Iterator, Self


class TaggedValue:
    """
    This is small extension of bytes, that allows to add "tag" and "iteration number" to bytes value.
    Considering hash-based signatures very often generate a lot of random bytes and hash them, this allows us to
    know when exactly was given value created and how many times it was already hashed.

    FOR EDUCATIONAL PURPOSES ONLY, OBVIOUSLY VERY WRONG TO USE THIS CLASS FOR REALWORLD PURPOSES.

    Attributes:
        NEXT_TAG: this number will be used to tag next value when tag is not provided


    """


    NEXT_TAG: int = 1

    def __init__(self,
                 value: bytes,
                 tag: str | int = None,
                 iteration: int = 0):
        """
        Creates new instance for value. Adds tag (either supplemented or from NEXT_TAG) and sets iteration to given
        number or 0.


        Args:
            value: actual bytes value of this TaggedValue
            tag: added tag, that should be unique for given run
            iteration: how many times was has function used to this value?
        """

        if not tag:
            self.tag =  type(self).NEXT_TAG
            type(self).NEXT_TAG += 1
        else:
            self.tag = tag

        self.iteration = iteration
        self.value = value



    def update_value(self,
                     new_value: bytes
                     ) -> None:
        """
        Set value to new_value and increments iteration count. It is called when hash function is used.

        Args:
            new_value: new value to set value to

        """

        self.iteration += 1
        self.value = new_value

    def __len__(self
                ) -> int:
        """
        Computes of value in bytes.

        Returns:
            value length

        """

        return len(self.value)

    def __iter__(self
                 ) -> Iterator[int]:
        """
        Iterates through value and returns integer representation of next byte.

        Returns:
            Integer representation of next byte.
        """

        for i in self.value:
            yield i

    def __repr__(self
                 ) -> str:
        """
        Returns string representation of this instance.

        Returns:
            string representation of this instance.

        """
        return f"{self.tag}|{self.iteration}|{self.value.hex()[:8]}"

    def copy(self
             ) -> Self:
        """
        Returns deep copy of this instance.

        Returns:
            Deep copy of this instance.

        """

        return TaggedValue(self.value, self.tag, self.iteration)

    def __eq__(self,
               other: Self
               ) -> bool:
        """
        Compares if other instance value is equal to this instance value.

        Args:
            other: Instance of TaggedValue to compare to

        Returns:
            Do these two instances have same value?

        """

        if not isinstance(other, type(self)):
            raise ValueError(f"Cannot compare TaggedValue to {type(other)}")

        if self.value == other.value:
            return True

        return False

    def __getitem__(self,
                    item: int
                    ) -> int:
        """
        Returns integer representation of value on specific location given by item attribute

        Args:
            item: Byte number inside value that should be returned

        Returns:
            integer representation of byte on given place
        """

        return self.value[item]

    def to_base(self,
                base: int,
                output_length: int = 0
                ) -> list[int]:
        """
        Converts value into list of values of given base. Can be prepended by zeroes to specific length
        given by output_length. If result is longer that output_length, output_length parameter is ignored.

        Args:
            base: base to convert value to
            output_length: minimum output length

        Returns:
            list of integers representing value in given base
        """

        if not isinstance(base, int):
            raise ValueError(f"Base: expected int, got: {type(base)}")

        if base < 2:
            raise ValueError(f"Cannot convert to base {base}")

        if not isinstance(output_length, int):
            raise ValueError(f"Output_length: expected int, got {type(output_length)}")

        bigint = int.from_bytes(self.value)

        result = []
        if bigint == 0:
            return [0]

        while bigint > 0:
            bigint, r = divmod(bigint, base)
            result.append(r)

        while len(result) < output_length:
            result.append(0)

        result.reverse()

        return result

    @classmethod
    def from_base(cls,
                  value_list: list[int],
                  base: int,
                  expected_length: int
                  ) -> Self:

        full_number = 0

        max_inc = len(value_list)

        for v in range(len(value_list)):
            full_number += base**(max_inc-v-1) * value_list[v]

        return cls(int.to_bytes(full_number, expected_length))