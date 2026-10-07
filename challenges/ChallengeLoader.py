import json

from src.base.BaseAlgorithm import Signature
from src.NaiveSignature.NaiveSignature import NaiveSignature, NaiveKeyPair
from src.LamportSignature.LamportSignature import LamportSignature, LamportKeyPair

def load_challenge(file_name):
    with open(file_name, "r") as f:
        challenge_data = json.load(f)

    if not challenge_data["algorithm"]["class_name"]:
        raise ValueError(f"Not proper challenge file")

    match challenge_data["algorithm"]["class_name"]:
        case "Naive":
            alg_primitive = NaiveSignature
            kp_primitive = NaiveKeyPair
        case "Lamport":
            alg_primitive = LamportSignature
            kp_primitive = LamportKeyPair
        case _ :
            raise NotImplementedError(f'Unknown class_name {challenge_data["algorithm"]["class_name"]}')

    alg = alg_primitive.load_data(challenge_data["algorithm"])
    if "keypair" in challenge_data:
        keypair = kp_primitive.load_data(challenge_data["keypair"])
    else:
        keypair = None

    signatures = []
    if "signatures" in challenge_data:
        for s in challenge_data["signatures"]:
            signatures.append(Signature(**s))

    return alg, keypair, signatures