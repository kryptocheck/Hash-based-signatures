from challenges.ChallengeLoader import load_challenge
from src.base.TaggedValue import TaggedValue


if __name__ == "__main__":
    # Loading challenge data into algorithm class , keypair class and list of signatures
    alg, keypair, signatures = load_challenge("02_parameters.json")
    forged_message_template = b'48652146|55555555|100|'

    forgery_candidate_hash = []
    forged_signature = None




    # Validate forged signature.
    verification = alg.verify(forged_signature, keypair.public_key, forged_message_template)

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

