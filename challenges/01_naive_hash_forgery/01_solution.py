from challenges.ChallengeLoader import load_challenge
from src.base.TaggedValue import TaggedValue

if __name__ == "__main__":
    # Loading challenge data into algorithm class , keypair class and list of signatures
    alg, keypair, signatures = load_challenge("01_parameters.json")

    # Getting signed_hash from known signature
    signed_hash = signatures[0].signed_hash.to_base(2)

    # Finding first position of 0 in signed_hash
    index = None
    for ind, i in enumerate(signed_hash):
        if i == 0:
            index = ind
            break

    # Create forged_signed_hash by changing part on this position to 1 and transform it back to bytes
    forged_signed_hash = signed_hash[:]
    forged_signed_hash[index] = 1
    forged_signed_hash = TaggedValue.from_base(forged_signed_hash,2, 32)

    # Create forged_signature by taking valid signature and hashing value on this position
    forged_signature = signatures[0].signature[:]
    forged_signature[index] = alg.compute_hash(forged_signature[index].copy())

    # Validate forged signature. We need to set already_hashed so algorithm won't hash our data again
    verification = alg.verify(forged_signature, keypair.public_key, forged_signed_hash, already_hashed=True)

    if forged_signed_hash == signatures[0].signed_hash:
        verification = False
        print("This is not forgery")

    print(f"Signature was verified: {verification}")




