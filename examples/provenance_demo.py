# -*- coding: utf-8 -*-
"""ML dataset provenance, end to end: sign -> distribute -> poison -> catch.

Scenario: a data team ships a fine-tuning set to an ML team. Annotator
emails (PII) travel encrypted. Somewhere in transit, one label gets
flipped. CI catches it and names the exact chunk.
"""
import os, random, tempfile, zipfile
import pandas as pd
import surframe

random.seed(7)
work = tempfile.mkdtemp()
path = os.path.join(work, "finetune-v3.surx")

print("== 1. DATA TEAM: build, encrypt PII, sign ==")
df = pd.DataFrame({
    "prompt": [f"Classify the sentiment of review #{i}" for i in range(3000)],
    "completion": [random.choice(["positive", "negative"]) for _ in range(3000)],
    "source": [random.choice(["web", "vendor", "synthetic"]) for _ in range(3000)],
    "annotator_email": [f"annotator{i % 40}@vendor.example" for i in range(3000)],
})
surframe.write(df, path, partition_by=["source"])
surframe.encrypt_columns_in_surx(path, ["annotator_email"], passphrase="pii-key")
kp = surframe.generate_keypair()
surframe.sign_container(path, kp.private_hex, signer="data-team@release-v3")
print(f"   {len(df)} rows, 3 partitions, PII encrypted, signed.")
print(f"   Publish this pubkey: {kp.public_hex[:24]}...")

print("\n== 2. ML TEAM: verify before training (no passphrase needed) ==")
rep = surframe.verify_container(path, kp.public_hex)
print(f"   valid={rep['valid']} signer={rep['signer']}")
assert rep["valid"]
sample = surframe.read(path, where="source == 'vendor'", columns=["prompt", "completion"])
print(f"   Queried {len(sample)} vendor rows without touching PII.")

print("\n== 3. ATTACKER: flip one byte inside one chunk ==")
zin = zipfile.ZipFile(path); data = {n: zin.read(n) for n in zin.namelist()}; zin.close()
target = [n for n in data if n.endswith(".parquet")][1]
b = bytearray(data[target]); b[200] ^= 0x01; data[target] = bytes(b)
with zipfile.ZipFile(path, "w") as z:
    for n, d in data.items():
        z.writestr(n, d)
print(f"   Poisoned: {target}")

print("\n== 4. CI: surx verify ==")
rep = surframe.verify_container(path, kp.public_hex)
print(f"   valid={rep['valid']}")
print(f"   reason: {rep['reason']}")
print(f"   modified: {rep['modified']}")
assert not rep["valid"] and target in rep["modified"]
print("\nCaught. The exact chunk, not a vague checksum mismatch.")
