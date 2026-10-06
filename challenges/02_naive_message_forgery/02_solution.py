from challenges.ChallengeLoader import load_challenge
from src.base.TaggedValue import TaggedValue

if __name__ == "__main__":
    # Loading challenge data into algorithm class, keypair class and list of signatures
    alg, keypair, signatures = load_challenge("02_parameters.json")
    forged_message_template = b'48652146|55555555|100|'

    # Getting list of signed_hashes from known signatures in base 2 representation (list of lists)
    signed_hashes = [sig.signed_hash.to_base(2, 256) for sig in signatures]


    # Joining all lists and searching lowest number on each position - 0 means we know private key on that position
    # and can forge both values, 1 means we can only forge value 1 on that position
    minimums, min_positions = alg.get_minimums_in_lists(signed_hashes)

    # Exhaustively searching for message with hash that allows us to build forged signature - there cannot be
    # situation where in message hash is 0 and at same position on minimums list is 1
    # (the only way we CANNOT forge that bit)

    addition = b'a'
    forged_signature = []
    while True:
        forged_message_template += addition
        forgery_candidate_hash = alg.compute_hash(forged_message_template).to_base(2, 256)

        # We can use the same function to compare our known values to forgery candidate, because ties go to first list.
        # When sum of second output is 0, that means that for each position value in first list (known values)
        # is not bigger than value on that position (meaning forgery is possible).
        _, comparison = alg.get_minimums_in_lists([minimums, forgery_candidate_hash])
        if sum(comparison) != 0:
            continue
        else:
            # Now we know forged_message and its hash, co we can actually build forged signature
            for index, i in enumerate(forgery_candidate_hash):
                next_value = signatures[min_positions[index]].signature[index]

                # When bit on given index is 1, we need to hash value on that specific part, but not when we
                # don't know private key on that position, only public key (meaning minimums[index] == 1)
                if i == 1 and minimums[index] == 0:
                    next_value = alg.compute_hash(next_value)

                forged_signature.append(next_value)

            # Encode forgery_candidate_hash back into bytes
            forgery_candidate_hash = TaggedValue.from_base(forgery_candidate_hash, 2, 256)

            break


    # Validate forged signature.
    verification = alg.verify(forged_signature, keypair.public_key, forged_message_template)

    # Check that you did not try just copying valid signature :)
    if forgery_candidate_hash == signatures[0].signed_hash:
        verification = False
        print("This is not forgery")

    # Checks that forged message have proper format
    if forged_message_template.find(b'48652146|55555555|100|') != 0:
        verification = False
        print("Forged message don't have proper format")

    print(f"Signature was verified: {verification}")




