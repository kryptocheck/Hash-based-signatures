from challenges.ChallengeLoader import load_challenge

if __name__ == "__main__":
    # Loading challenge data into algorithm class , keypair class and list of signatures (empty in this case)
    alg, keypair, signatures = load_challenge("00_parameters.json")

    # Generating signature
    message = b'Sample data for signature'
    signature = alg.sign(message, keypair.private_key)

    # Signature verification
    verification = alg.verify(signature, keypair.public_key, message)
    print(f"Signature was verified: {verification}")
