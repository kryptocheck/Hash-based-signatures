05_winternitz_hash_forgery_I
=======================
Your goal is to create forged signature for random hash. You do not need to forge signature of whole MESSAGE (for now), 
just forgery of random hash.  
You will be given 2 valid signatures and that is all you will need.
For this challenge, Winternitz parameter *w* will be set to 2, so it will be as similar as possible to challenges for
Naive and Lamport signatures.

Tips:


Old Tips:
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

