from challenges.ChallengeLoader import load_challenge
from src.base.TaggedValue import TaggedValue

if __name__ == "__main__":
    # Loading challenge data into algorithm class, keypair class and list of signatures
    alg, keypair, signatures = load_challenge("04_parameters.json")
    forged_message_template = b'48652146|55555555|100|'

    # Getting list of signed_hashes from known signatures in base 2 representation (list of lists)
    signed_hashes = [sig.signed_hash.to_base(2, 256) for sig in signatures]




    # Joining all lists and searching what values for each position I actually know and can forge
    values_overview = alg.get_values_on_all_positions(signed_hashes)

    # Exhaustively searching for message with hash that allows us to build forged signature -
    # on each position we need to know that specific value, otherwise we cannot forge signature of this message


    addition = b'a'
    while True:
        valid_forgery = True
        forged_message_template += addition
        forgery_candidate_hash = alg.compute_hash(forged_message_template).to_base(2, 256)

        forged_signature_value = []

        # Let's check known values on each position and either add it to signature or break completely when
        # we don't know that value
        for index, i in enumerate(forgery_candidate_hash):
            if i not in values_overview[index]:
                valid_forgery = False
                break

            # Search in what signature was value we need used and copy it from that signature
            signature_index = values_overview[index][i][0]
            forged_signature_value.append(signatures[signature_index].signature[index].copy())


        if valid_forgery:
            # Encode forgery_candidate_hash back into bytes
            forgery_candidate_hash = TaggedValue.from_base(forgery_candidate_hash, 2, 256)
            break


    # Validate forged signature
    verification = alg.verify(forged_signature_value, keypair.public_key, forged_message_template)

    # Check that you did not try just copying valid signature :)
    for s in signatures:
        if forgery_candidate_hash == s.signed_hash:
            verification = False
            print("This is not forgery")

    # Checks that forged message have proper format
    if forged_message_template.find(b'48652146|55555555|100|') != 0:
        verification = False
        print("Forged message don't have proper format")

    print(f"Signature was verified: {verification}")




