from challenges.ChallengeLoader import load_challenge

if __name__ == "__main__":
    # Loading challenge data into algorithm class , keypair class and list of signatures
    alg, keypair, signatures = load_challenge("05_parameters.json")
    w = 2

    # Switch this to your forged message/signature pair
    forged_signature = None
    forged_signed_hash = None


    # Validate forged signature. We need to set already_hashed so algorithm won't hash our data again
    verification = alg.verify(forged_signature, keypair.public_key, forged_signed_hash, already_hashed=True)

    if forged_signed_hash == signatures[0].signed_hash or forged_signed_hash == signatures[1].signed_hash:
        verification = False
        print("This is not forgery")

    print(f"Signature was verified: {verification}")