# reused-r-bitcoin
Detection & research tools for repeated ECDSA & Schnorr nonces (r) in Bitcoin transactions



⚠️ important :

these tools are for educational purposes. Any incorrect or harmful use is the responsibility of the user.

What is “r-repeat” :

r-repeat means the same ECDSA or Schnorr nonce (k) — and thus the same r value — was used more than once with the same private key in Bitcoin signatures. If that happens, the signatures leak enough information that someone could recover the private key. This turns otherwise secure signatures into a critical vulnerability.

How does r repeat? :
1. Weak or insufficient randomness (CSPRNG): the system or device didn’t provide enough entropy when signing.
2. Programming bug: the random generator is re-seeded incorrectly or the same nonce buffer is reused.
3. Incorrect deterministic nonce implementation: RFC6979 is safe when implemented correctly; buggy implementations break safety.
4. Re-using the same private key across apps / chains: one weak environment can compromise all signatures made with that key.
5. Weak key-generation (brainwallets): low-entropy passphrases or predictable key derivation lead to weak keys and weak nonces.
6. Hardware / firmware faults: buggy devices can unintentionally reuse nonces (e.g., after power loss).

   Why is this dangerous :
   
Because the nonce k is the core secret that makes each signature unique. If the same k is used twice with the same private key, the signatures alone (no access to the private key required) may allow an attacker to compute the private key. In short: nonce reuse breaks the security goal of signatures.

What you should do (safety tips) :
1. Use well-audited libraries (e.g., secp256k1/OpenSSL) and keep them updated.
2. Prefer RFC6979 deterministic signing only via proven implementations.
3. Use hardware wallets or HSMs with good security reviews for high-value keys.
4. Never reuse a private key across unrelated apps/chains.
5. Avoid brainwallets or passwords-as-keys; use proper key generation.
6. Monitor signatures: detect repeated r values and act immediately if found.

Requirements :

Python 3.10 or newer

Sufficient free storage space to download transaction data (depends on analysis size)

Internet connection when fetching blockchain data or using APIs

Security Notice :

These tools are designed purely for analysis and research — they do not collect any user data, results, or personal information in any form.

Running the tools with an internet connection is safe, as long as you trust the source.

You can always review the source code yourself to verify what each tool does and ensure it meets your security standards.

Required Python Packages :

The scripts require the following Python libraries:
```bash
• requests
```
pip install requests

• tqdm

pip install tqdm

• ecdsa

pip install ecdsa