from challenges.ChallengeLoader import load_challenge
from src.base.TaggedValue import TaggedValue

if __name__ == "__main__":
    # Loading challenge data into algorithm class , keypair class and list of signatures
    alg, keypair, signatures = load_challenge("05_parameters.json")
    w = 2

    # Getting signed_hashes from both known signatures
    signed_hashes = [sig.signed_hash.to_base(w, 256) for sig in signatures]


    # Finding first positions where value for both hashes differ for each combination 0->1 and 1->0 - that way we can
    # create forgery without touching that checksum part.
    index = [-1, -1]
    for ind, i in enumerate(signed_hashes[0]):
        if i != signed_hashes[1][ind]:
            index[i] = ind

        if index[0] > -1 and index[1] > -1:
            break

    # Create forged_signed_hash by taking first signed_hash and changing value on given position
    # to value from second signed_hash
    forged_signed_hash = signed_hashes[0][:]
    forged_signed_hash[index[0]] = signed_hashes[1][index[0]]
    forged_signed_hash[index[1]] = signed_hashes[1][index[1]]
    forged_signed_hash = TaggedValue.from_base(forged_signed_hash,2, 32)

    # Create forged_signature by taking first signature and changing value on given position
    # to value from second signature
    forged_signature = signatures[0].signature[:]
    forged_signature[index[0]] = signatures[1].signature[index[0]].copy()
    forged_signature[index[1]] = signatures[1].signature[index[1]].copy()

    # Validate forged signature. We need to set already_hashed so algorithm won't hash our data again
    verification = alg.verify(forged_signature, keypair.public_key, forged_signed_hash, already_hashed=True)

    if forged_signed_hash == signatures[0].signed_hash or forged_signed_hash == signatures[1].signed_hash:
        verification = False
        print("This is not forgery")

    print(f"Signature was verified: {verification}")




