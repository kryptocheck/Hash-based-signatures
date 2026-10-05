00_introduction
================
Before we start breaking signature schemes, let's try using one properly. You are given private and public key, 
use it to create and verify signature using Naive signature algorithm.

Tips:
* keys are loaded into keypair.private_key and keypair.public_key 
* message can be any bytestring, for example b'Sample data for signature'
* use signature = alg.sign(message, private_key) to generate signature
* use verified = alg.verify(signature, public_key, message) to verify signature
