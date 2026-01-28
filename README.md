# CPSC4130 GPG Key Exchange

A repository for exchanging GPG public keys for the key signing assignment. All for one, and one for all.

## Prerequisite
- python3
- gpg
   - Make sure the default gpg dir contains your private key

## Repository Structure

```
Key-Exchange/
├── course_key.asc              # Course public key
├── keys/                       # Everyone's public keys (course-signed)
│   ├── ab123.asc
│   └── ...
├── signed/                     # Signatures made by each person
│   ├── ab123/                  # Signatures made BY ab123
│   │   ├── cd456.asc
│   │   └── ...
│   └── ...
├── scripts/
│   ├── collect_signatures.py   # Collect signatures on your key from signed/
│   ├── gpg_utils.py            # Core module - shared GPG utilities
│   ├── sign_all.py             # Sign all verified keys in keys/
│   └── verify_key.py           # Verify key files have course signature
├── sign_all.sh                 # Sign all verified keys
└── collect_signatures.sh       # Collect signatures on your key
```

## Quick Start

### Step 1: Submit Your Key (One Time)

1. Fork this repository
2. Setup upstream
```bash
git remote add upstream https://github.com/VitaLemonCoffee/Key-Exchange.git

git fetch upstream
git merge upstream/main
git push
```
3. Add your public key to `keys/<netid>.asc`
   - **Must be the course-signed version** (from Canvas after submission)
4. Create a Pull Request
   - CI will verify your key has the course signature
   - CI will reject files outside `keys/*.asc` or `signed/*/*.asc`
5. Wait for merge (ideally, a pull request pass the status check will be merged automatically)

To use the scripts in the following steps, please in the root directory of the repository do
```
echo "<your-net-id>" > .netid
```

### Step 2: Sign Everyone's Keys
Note: This step is repeatable. Feel free to rerun when someone needs signatures from you.

#### Method 1 (sign automatically)
pull latest keys.
```bash
git pull upstream main
```

Run the signing script to automatically generate signed keys.
```bash
sh ./sign_all.sh
```

Commit your changes and create a PR from the main branch of the forked repository to the main branch on the github web portal or using extensions in your IDE.

#### Method 2 (sign manually)
pull latest keys.
```bash
git pull upstream main
```

For each `keys/<netID>.asc`, verify its signature and sign it. Place the signed key under `signed/<your-netID>/<signee-netID>.asc` and commit.

Commit your changes and create a PR from the main branch of the forked repository to the main branch on the github web portal or using extensions in your IDE.

### Step 3: Collect Signatures on Your Key

```bash
# Pull latest (after others have signed)
git pull upstream main

# Run the collection script
sh ./collect_signatures.sh

# Export your key with all signatures
gpg --export --armor "your-email@yale.edu" > my_key_final.asc
```

## PR Rules

PRs may only add files matching:
- `keys/<netid>.asc` - Your course-signed public key
- `signed/<your-netid>/<other-netid>.asc` - Your signatures on others' keys

Any other files will be rejected by CI.

## Manual Verification

```bash
gpg --import keys/<netid>.asc
gpg --check-sigs <netid>@yale.edu
```

Look for:
```
sig!         A049C765A07C89D8 2026-MM-YY  CPSC4130
```

## Course Key Fingerprint

```
4DD5 B379 1798 E493 F649  9F8D A049 C765 A07C 89D8
```

## FAQ

**Q: CI failed on my key submission?**\
A: You probably submitted your original key, not the course-signed version.

**Q: How do I check my progress?**\
A: Run `./collect_signatures.sh`

**Q: Can adversarial keys sneak in?**\
A: No (as long as you trust the manager of this repo) - CI verifies course signature on all keys in `keys/`. The `sign_all.sh` script also verifies before signing.

**Q: Does adding my key to this repo guarantee that I will get enough signatures?**\
A: No - This repo only provides convenient tools for automated signing, but there is no enforcement of signing. Also, keys added later are likely to get fewer signatures.

**Q: I am an attacker, how should I put adversarial keys into this repo?**\
A: Try to hack github.

**Q: I encountered a bug / I have another question.**\
A: Discuss in github issues or Ed.