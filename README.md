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

• requests
```bash
pip install requests
```
• tqdm
```bash
pip install tqdm
```
• ecdsa
```bash
pip install ecdsa
```
How to operate tools + example :

This is a list of addresses that included the r-duplication vulnerability :
```bash
1HXSnvNGK8oYQCyLDkpHNZ2sWPvFsYQcFU
112KZ24UgNndZqdnu2cXwXStSjtY78ZRUh
12ZXAga2nRxBECsMDjFypWuL9UkKEaS4Z3
12sisxXmNPmFTpekBKEqZCELYXESPYUHCB
139YrtXS2J1KiD8pf2R3RtKRPr8sLwLuiq
13GSuGxtMZyE6SDA8XJyuWsHYpXZyNQTAn
13ikC8398HhciFWkqPCrRHWUBASGxhBY4m
13tRCNGCGuVN4gYyf6CpfYckhM3qrJy9YX
14Bgi1c11HBcj7krN5tRepMdL3SPghEaMM
14kaXa47cUcMpvKnCa8zr38C9v7sVPxSta
14qF25Rg3hJaYFHwE6ST2rr1cnBS3DPYNe
14uS988CkkfTs7Ckre8nkVedSQF9v4CqrM
1599DB5Tb1RWDPYMuU3YJT3jRwyyoPZa1B
15Ew6Sen8hVhTfLmXvAEEqGfX58iYWqEV5
15mcUhVMi3KmoWvP6Y8NpVaXaPVGCWztgL
1681LkMDLNw6CCjUrMojRKC8BaiwQ2LTFt
16LEKMzhabDoTghR2no3a59SJQC6MJp2aM
16NMGWRavnYG5bhWzY8GAXWiTZLytpT4v7
16khUbFwUK6X7U5X919RJeWyfBHSLfJMda
16vHYDZCLZiD97TucWr5Wht9zBA7JJmuF5
17SP6Qc3fP3zUWFkfRrwY3TF3a6eQ3NsZr
17Vxv31VfpFY6tWBBB93tcSgP4SYeqzTTb
17quWZhtGikUcTUpExchL6UdFga6Z8hME9
17xnTfrWYiLMhEQmW55VCa5cVhSZMVUak6
181ErGfBCT7twckweWJgoDMGXNepvb4qnp
185YGf4EoVfgqFBSAAUf1wDte9KVwmdHMy
187TT5PpAKGHRBGjdaKDZsgBH1s8yNCtS4
18RecXQxH8xuqS1zNgrukvPybDtc3Mn4br
18SEPGaZ3xdHiH2hkSdPgkYdnvzPr6PZYS
18U2grD3VwFa626tkTnabXSY2nVQAvmf3U
18W9kV7SqNPnvcbZRzM34aE14m5tFmAuz5
18djF84ZNVURvFUX2ZAVaFqV9MerjJkQtE
18mEp3aKQ9thp3H72rrzHAfW719YmHq2f7
199EPbUzU6mBr7dP61ihWsicuJyeYbJviS
19Ey6feEfARgzcNRmUxBZNQFYSmwgsU9Wc
19usDGaGtwHfMoJKAJEJd3KcfZFWj5zocV
19vokfKSJJMwHAqQ3Kehk8Gq5drXhi7wzU
1AApKu3su7VT9K1hgyxp3pcp2DSNC5V9s3
1AFZ8j6Mm6EphAFJbHyzCxKpKm9si8Vt3v
1AGCK1JM7pEu5r4g5yRiezXhn83TPGaWEh
1AKE18rv9BUPpxciQziTjQzwNQoMSrvQaV
1AX5hvrNXTs8KnDVBSRwHPHg5iQ5fyb8rs
1AjwULXBv9TeVjADC3khcP69USBGRXYUpd
1ArJ9vRaQcoQ29mTWZH768AmRwzb6Zif1z
1AsEhnbniTP4YSA8L1Xa1uQjfSfHbb8tzJ
1AsbDvSw2rzEa39erkCrMW6KTr4tDHGSAH
1Asfz56unNm1c527p3ENavRqecShQyxHeN
1B9FoQWdPift6CUXUs6K82TZxaTyHpTUnC
1BDMV3Yb6Pp2ycB94UsruXgPWAWBJhBuKL
1BYuQ21smrF1hKfmHPsDnJkWZZdEpBFLZo
1Bn1n2N9Z3Xhnxd3b6ViNMstg7oGjh8XAa
1BwrmTmhnp6K6Shbq5zQQqGqnsfXsunsqE
1C4YepY3K1gDrRiQ5E9rgaJuXvrawxXMJG
1CAsRJ5Z9CXdhBwxrCVrf8kJNPBxYQJiH1
1CLfNqGBb949bBbMgefRPkDVgpgyEgWRF
1CPzjQTH5vNADXQGeCfHtRgX8S5xMLGMr4
1Cbw9MZ8Vrfkzv1FxuJS5JBySbypuMARQj
1CgEzXmF7SeNr8rd2AfyN1DQNJpprVxWmW
1CjKefUiRhK5hWf79MoJqccHC1ohye7SWr
1CpV2F9YASreNrBGf1E8QgFgKdqYQopzGH
1CtgapxmS4CRLCNFGTbidAqfk9WNdR2kdn
1D76ha9QoxkUPLxufDoZVEzx6hH3uVJvnZ
1DEsbC42Je7psYeaE2mbWNUpSEFTL9aQUs
1DL21hg5FBLC4h9mXwx9XDbHmUK3BZFCQe
1DkCk3S98BCwPP8wdmxqQKcQoH4WJthvMR
1DpyhFtQs3yVM4gSf3KiD9GBxcPaxuQRDT
1DqXkT8KR25q56sAerfSg875KaJ6o3f3mi
1Dsoi4eggJhipmYZtFGPGBxLX8nguYxiGh
1DxzwX4qC9PsWDSAzuWbJRzEwdGx3n9CJB
1E1rbpZitcZ73JQoLYXB18pDm8BTHVqxtk
1EGok6kAbJRrzryXAGyCHRq5c649rhzwJ3
1EKJUnK4EE83LdGsCnFPZxgkybyFiTdbMk
1EMkFrY86siasW3F9zC2bS1ZcSuTdaiJqj
1EMxjb3667se6LuqkhRsrBaAScGsx5DMFq
1EZtDBBkqkHxRXNSBwTV7HhBbPVvqC8Rte
1EkkAMw1K6HKGiou5vNrLBffDtjVAC5HW3
1EqBqwtfJMZERvyckvexLJLuSrqYewCaE3
1Es37FWCT3xDCrQM2NEJLajRPYNbk7jUaH
1FMhAUpVgU2H3n576vUe7vQp94zCkRPnf6
1FSmh8gSuPkZTqx6LeH6Jic4iZ1A8BsZ2L
1FyQtBr9ub8FhKGDcgW2uAbU6cHYuNmBk3
1GNvTWNZM48QA44QmbVjxXhQ7hmJDicxec
1GvhZ6FewuuyYwZ9cPWd614Gu6UhWacrDY
1HAEJNWN7johTEiooRau7F6NFvHnBDXHzh
1HDGRnafT7ogCaMuHx9csBGvGeYc441tQ4
1HMYjeeZf4qq9L9WZRaBKnNjsP1bSLsuMs
1HSUdtBoNbexP3ordhnSZ2jfHCGVvAbGt
1HW45VWikPEoijyKtguggMEJ5CnsS78ESf
1HfjrpJLP5SaPRFzYUxrzhppw6xv6GXZ6f
1Hu5wfuk9nHuYDpdX6FjQrU1NYvpUS8r6t
1JHL7mbGq64heFnJA8i2QVm18p4TQ1kf9M
1JX7Z9Si6tUQgFa4PLNTtJ8bC9WrfMDvLb
1JmY6KZxoMjMaFKLVSMAr7BdsAAWASMR7d
1K3iZPSqMCxtMd5o5hw4gfpFq3i9zqL61o
1K8fu7jfjuKS28YrA2rSCy7fkZhNvcab5p
1KJERjQwXx8ojrKRSPFKwkCct1aAkyHgnF
1KS7abb8CrqrSizfyPXkcRocYejZQ332xM
1KiAVfFJH9EU29C9H9p2SBnrkfzrgrRRCe
1KojFMcdHzDndhfqPxb5CnXeB1R5u9nnxG
1KpxMLLmEhaqoUXN1hfq8fci4z7p593HsV
1KvvnDBRtHFZdE9ngqGWV5VGznFgXuF1fd
1Kzf3YptWEMwDHF1nmVpMbs3jSvWjWdSbR
1L2Bcohuf1qyHykTdP8rD74K6HQSsTaTE
1LCnNsa2pxbZCsVdRoNqLGFcULbrEFL4i1
1LKVE8ys5rep3LbELC3fhfCRWXQiEi7hpv
1LKumxgbfSycQVaAwagpyZRSy71wXC2zhF
1LWDzisQtETsxk6N8QNa1KuUSiYtmmfa5A
1LhA9wbU4enUCT8EVorxeJegQtkZcyr7m6
1LrUd8tr5TD3UvD4KZaiNcAxmFveCw5h27
1M52izWFApBEuRMqMx4gbr8prABCA9Q9tv
1M7hSnVZniAXrre2SH9qaHvfxgXRAjpMVk
1MLQDQQsaHPSPQwp3TJ5YSbffm2EHneaU9
1MMMpX4AKhf9JTviWuU7fwnZuTdW78G2Mf
1MX1fSzSvTuw3yNgPNE3Ni31kT1DSdeUPC
1MmJk1peLVmycqY8Hq6WyZfrK4u1oTvkER
1NAddQ2XhM96aGn4yK9naRzxTxe7BbNTLG
1NLbWbTczixoA3sCgQg5NLpsExqRPJiA3H
1NMb6g4rQXHmsaHaiy1iV2Wmn4bTGwxyLT
1NR7Bw4XWK3oic9HvgWFProGVzp5jKeqCw
1NWXH2DE5DTfKWAwABAvFesGXKkyKBUoiN
1NeAtszct9Uav81CEr1FGhV4KAaXahdsVF
1NjGEKWWrupvbzvEivnfXJpdNdXK5xzdDb
1NkYPP3Eix9shAvU47xJtnL4Ggd2ScAbcD
1P5anXJVbPeXsw4wExuQ8SCBRevRPe8syQ
1PEAu3bS7t6ZYKGX77ZJsEKSupGzdR5Kpj
1PNa9dZ3P3fVhx1uMCqJ4sEYmyhxnQNy3M
1PQwoVNRCiK2J5GNumfpT3qk7KnhKPJ6Ph
1PVHbRqh1eYsGCVZ7t18UCQ6oPzXFR3HQz
1QBYgXMTqEQNgoVotQN2iP1sPhHRPEoDHb
1QDB2W1VFqinxu5zm4qMGecQTfviBjk3JA
1RfEM5WPtboTNnjHN3HR889FyuUx6T14D
1ZaRiG4qLj336tKFMZCGPpySoRQsReivv
1iuC1ovtbMJQLniEiJtR5obbWvVkmTjiE
1ptDzNsRy3CtGm8bGEfqx58PfGERmXCgs
1sgNrgAnjMVSzyeMDTeVsKN7FuZy34U5t
1vdbVPC6Ts9d5WhRDriPdndvvCwmCbKCj
```
Let's choose this address
```bash
1HXSnvNGK8oYQCyLDkpHNZ2sWPvFsYQcFU
```
1• collecting transactions

Raw transactions containing values and signatures
```bash
fetch_raw_txs.py
```
This script collects raw transactions from a target address.

usage :
```bash
python3 fetch_raw_txs.py -a 1HXSnvNGK8oYQCyLDkpHNZ2sWPvFsYQcFU --output results.csv --rawtxt rawtxs.txt
```
```bash
python3 fetch_raw_txs.py -a 1HXSnvNGK8oYQCyLDkpHNZ2sWPvFsYQcFU --output results.csv --rawtxt rawtxs.txt --resume --append
```
rawtxs.txt is file that contains raw transactions is automatically generated by script

fetch_state.json is state file automatically generated by script

You can use command (--resume --append) To continue collecting transactions where left off 
```bash
frt_ultra.py
```
This script like the first one, but with advanced options.

For example, we have this address 
```bash
1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```
This address has over 52,000 transactions, and that's a large number, Let's say you only want the 100 oldest transactions

First, you will enter this explorer
```bash
https://bitcoin.atomicwallet.io/address/1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
```
This explorer allows you to browse all transactions, even if there are many, without loading each transaction into a very long sequence.

Each page contains 25 transactions, You will go to the last page, for example, page 2096 

Then calculate the number of transactions you want to collect. For example 

100÷25=4

1000÷25=40

10000÷25=400

Then subtract a number of pages from the total number.

2096-40=2056

usage :
```bash
python3 frt_ultra.py -a 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --start-page 2056 --end-page 2096
```
```bash
python3 frt_ultra.py -a 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa --start-page 2015 --end-page 2055 --resume --append
```
(--resume --append) command to continue collecting

2• analyze

Analyzing transactions to extract values used to calculate private key
```bash
analyze_txs_enhanced.py
```
This is script that analyzes

usage :
```bash
python3 analyze_txs_enhanced.py rawtxs.txt
```
This script will generate file named "der_full_summary.csv" containing values.

The file size can be so large that it is unreadable (file size depends on the analysis; for example, analyzing many transactions, such as 10,000 transactions, might produce a file size of 10+ GB).

You can use this script 
```bash
cut_r2.py
```
This script should be in the same folder as the csv file.

script will read csv file and extract all the lines in which "r" is repeated.

usage :
```bash
python3 cut_r2.py
```
Then you can change csv file name to "der_full_summary.csv" to continue working 
```bash
compute_z.py
```
This script calculates z value

usage :
```bash
python3 compute_z.py --input der_full_summary.csv --output der_with_z.csv --fetch-prevouts
```
The script will create a file named "der_with_z.csv". This file is required to calculate the private key. 

Additions :
```bash
ate_ultra.py
```
This script similar to analysis script, but with additional features such as sorting signatures according to protocol.

usage :
```bash
python3 ate_ultra.py rawtxs.txt
```
___________________________________________________
```bash
ext_schnorr_extras.py
```
This script extracts additional information for Schnorr Protocol

usage :
```bash
python3 ext_schnorr_extras.py rawtxs.txt --fetch-prev
```
3• computing private key

We will use "der_with_z.csv" file generated by command
```bash
python3 compute_z.py --input der_full_summary.csv --output der_with_z.csv --fetch-prevouts
```
because it contains all the values required to calculate the private key.

Required values :

repeated r value (r_hex In CSV file)

s value for each signature (s_hex In CSV file) (We need the value of the first and second signatures. If there are more than two signatures, you can switch between them)

z value for each signature (z_mod_n In CSV file) (Value of the first and second signatures)

The values must be integers.

z values (z_mod_n) is already integer

You must convert (r-s1-s2) values from Hex to an integer

You can use this script
```bash
hex_to_number.py
```
Create file named "hex.txt" and Write values in it, One line for each value

script will convert values and write them to new file.

usage :
```bash
python hex_to_number.py hex.txt
```
for example (1HXSnvNGK8oYQCyLDkpHNZ2sWPvFsYQcFU)

When analyzing the transactions of this address, we will find four instances (four signatures) of r repetition (one r value - four s value - four z value)

We will use values from the first and second signatures :

repeated r: hex(00cabc3692f1f7ba75a8572dc5d270b35bcc00650534f6e5ecd6338e55355454d5) int(91699739317935258627372771550459504326006289891191381848862551863464593478869)

s1: hex(00f65bfc44435a91814c142a3b8ee288a9183e6a3f012b84545d1fe334ccfac25e) int(111431484914827310314108809136597661506085346855505784425577929088113412063838)

s2: hex(00b584c5e2f26eaac9510307f466d13f8d4e8f57b1323cc4151ff6ffeb6747ca9b) int(82103215168631327946455936234377737221280608082064931975396899914217832303259)

z1: int(70121596733354710270739379126478863332897631323035990573894949033544740983882)

z2: int(42691526897907875236967398205101700537962275948723679969547592971981809076177)
```bash
compute_x.py
```
This script calculates the private key.

Before running it, you must open it with a text editor and change the values (r-s1-s2-z1-z2) (Do not change n value) (values must be integers)

usage :
```bash
python3 compute_x.py
```
script will print the results

for example:
```bash
s_diff = 29328269746195982367652872902219924284804738773440852450181029173895579760579
z_diff = 27430069835446835033771980921377162794935355374312310604347356061562931907705
k (decimal) = 12345678
k (hex)     = 0xbc614e
x (decimal) = 36985158630392181731692032973660058930135418234446520253368071243468798761122
x (hex)     = 0x51c4dba2c28fc89b208550477a514c87f9d0db0354f03b7c61f08c0a0e3118a2
verification ok: True
```
x (hex) is the private key

To convert x(hex) to WIF, use this script.
```bash
wif.py
```
Create file named "xhex.txt" and place it in the same folder, then write x(hex) values in it

script will read file and produce WIF (compressed / uncompressed) With all possibilities with derivatives for each type of address(p2pkh / p2sh / p2wpkh / p2tr), along with a balance check.

usage :
```bash
python3 wif.py --file xhex.txt --out mywifs.csv
```
file named "mywifs.csv" will be produced containing the results.

for example:
```bash
5JSJG3nX6z1rsfZ9EZTtbi4qy82TzjGLBpyPzGm7hPRazzrqYzA
```
This is WIF(uncompressed - p2pkh)to 1HXSnvNGK8oYQCyLDkpHNZ2sWPvFsYQcFU

Additions :
```bash
sc_r.py
```
This script calculates  private key for the schnorr protocol. 

usage :
```bash
python3 sc_r.py \
  --Rx 0a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef \
  --Px 1f2e3d4c5b6a79880796a5b4c3d2e1f0a9b8c7d6e5f40123456789abcdef0123 \
  --s1 0x8a3f1b2c4d5e6f7091a2b3c4d5e6f7089a1b2c3d4e5f60123456789abcdef012 \
  --m1 "hello world" \
  --s2 0x7b2e3c4d5f6a7b8091a2b3c4d5e6f70123456789abcdef0123456789abcdef01 \
  --m2 "other message"
```
Change the values

It will print the results  

For example :
```bash
=== Result ===
e1 = 108970234477436902694766334568020749912403966361468773267923272186995557531266e2 = 66856546383303793989981220542885447886729718496899420254699013163356773868462
s1 = 62530672011108711400438125813195380086512239951027680111811469263325183799314
s2 = 55716171531466744293207597776544084512684920955164725164723036609180125228801
s_diff (s1-s2 mod n) = 6814500479641967107230528036651295573827318995862954947088432654145058570513
e_diff (e1-e2 mod n) = 42113688094133108704785114025135302025674247864569353013224259023638783662804

Recovered private key x (decimal): 47206142724068971842463861168325724021122544036124670454439260535612937450174
Recovered private key x (hex)    : 0x685dbadd6c6726922fd9f2b703c7763b4cb00c7078fea84179664a7c0eb5b2be

WIF (mainnet, compressed): KziatDAHb89WXx8xB8uUbAAJ62LpDkGGpbv465vGHfpPzYGcddoQ
WIF (mainnet, uncompressed): 5JcFUTmhTmDMHXcnaZbzubhd3VrMDQPwngBD2c6iynx9PCyXBC1
```
Support the Project :

If you find this project useful or it helped you in any way, consider supporting me!

Donate :

BTC
```bash
bc1qtxctgmaxwh73h22h862epj3a7yc3tdl2j45aep
```
