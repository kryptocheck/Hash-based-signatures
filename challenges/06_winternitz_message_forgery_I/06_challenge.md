04_lamport_message_forgery
=========================

Now you will be actually creating forged signature of message in specific format.

Let's pretend I am payments processor. I am processing only data in this format:
* "[source_account]|[target_account]|[amount]|[description]"

* This whole message is then signed using Winternitz algorithm with w=2, but I am using the same keypair for all payments.

I already processed 4 payments ( = created 4 signatures with the same key).

Your goal is to forge valid message transferring amount "100" from source_account "48652146" into account
with number "55555555".


Tips:



Old tips:
* keys are loaded into keypair.private_key and keypair.public_key 
* know signatures are loaded into list signatures.
* use val.to_base(base) to convert bytes to list of integers of given base (base 2 to convert into binary) 
  (val need to be of a type TaggedValue)
* use TaggedValue.from_base(value_list, base, expected_length) to convert list of integers of given base back to bytes
* use signature = alg.sign(message, private_key) to generate signature
* use verified = alg.verify(signature, public_key, message) to verify signature
* you can use a,b = get_minimums_in_lists(list[list[int]]), that will return two lists - first list will contain 
  the smallest number for each position in all lists, second will contain for each position index of list where 
  that value was found