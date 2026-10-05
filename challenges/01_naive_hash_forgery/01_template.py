from challenges.ChallengeLoader import load_challenge

if __name__ == "__main__":
    # Loading challenge data into algorithm class , keypair class and list of signatures
    alg, keypair, signatures = load_challenge("01_parameters.json")

    # Switch this to your forged message/signature pair
    forged_signature = None
    forged_signed_hash = None

    verification = alg.verify(forged_signature, keypair.public_key, forged_signed_hash, already_hashed=True)
    print(f"Signature was verified: {verification}")

