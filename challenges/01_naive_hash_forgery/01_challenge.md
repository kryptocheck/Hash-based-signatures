01_naive_hash_forgery
=======================
Your goal is to create forged signature for random hash. You do not need to forge signature of whole MESSAGE (for now), 
just forgery of random hash.  
You will be given 1 valid signature and that is all you will need.

Tips:
* know signatures are loaded into list signatures.
* use val.to_base(base) to convert bytes to list of integers of given base (base 2 to convert into binary) 
  (val need to be of a type TaggedValue)
* use TaggedValue.from_base(value_list, base, expected_length) to convert list of integers of given base back to bytes

Old Tips:
* keys are loaded into keypair.private_key and keypair.public_key 
* use signature = alg.sign(message, private_key) to generate signature
* use verified = alg.verify(signature, public_key, message) to verify signature