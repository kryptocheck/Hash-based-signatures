import json

from src.NaiveSignature.NaiveSignature import NaiveSignature, NaiveKeyPair, Signature


def load_challenge(file_name):
    with open(file_name, "r") as f:
        challenge_data = json.load(f)

    if not challenge_data["algorithm"]["class_name"]:
        raise ValueError(f"Not proper challenge file")

    match challenge_data["algorithm"]["class_name"]:
        case "Naive":
            alg = NaiveSignature.load_data(challenge_data["algorithm"])
            if "keypair" in challenge_data:
                keypair = NaiveKeyPair.load_data(challenge_data["keypair"])
            else:
                keypair = None
        case _ :
            raise NotImplementedError(f'Unknown class_name {challenge_data["algorithm"]["class_name"]}')

    signatures = []
    if "signatures" in challenge_data:
        for s in challenge_data["signatures"]:
            signatures.append(Signature(**s))

    return alg, keypair, signatures