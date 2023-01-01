import json
from ecdsa.numbertheory import inverse_mod
import ecdsa


with open('data.json', 'r') as f:
    data = json.load(f)
r1 = data['sig_1.r']
r2 = data['sig_2.r']
assert r1 == r2
sig1 = int(data['sig_1.s'], 16)
sig2 = int(data['sig_2.s'], 16)
hash1 = int(data['hash1'], 16)
hash2 = int(data['hash2'], 16)
ORDER = data['order']

N = (((sig2 * hash1) % ORDER) - ((sig1 * hash2) % ORDER))
D = inverse_mod(r1 * ((sig1 - sig2) % ORDER), ORDER)

privateKey = N * D % ORDER

json.dump(
    {
        "privateKey": int(privateKey),
    },
    open("output.json", "w"),
)