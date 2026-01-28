#!/usr/bin/env python3
"""
GPG Key Verification and Signing Utilities for CPSC4130

Core module providing:
- Key verification (check course signature)
- Key signing (sign verified keys)
- Signature collection (gather signatures on your key)
"""

import subprocess
import tempfile
import shutil
import os
from dataclasses import dataclass
from typing import Optional

# Course key details
COURSE_FINGERPRINT = "4DD5B3791798E493F6499F8DA049C765A07C89D8"
COURSE_LONG_ID = COURSE_FINGERPRINT[-16:]  # A049C765A07C89D8

COURSE_PUBLIC_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaWh3GRYJKwYBBAHaRw8BAQdA3mQuK26f2ADap+bDwvLTsxzHX2g2HBIFJ2yM
DNnRcyi0CENQU0M0MTMwiJYEExYKAD4WIQRN1bN5F5jkk/ZJn42gScdloHyJ2AUC
aWh3GQIbAwUJAO1OAAULCQgHAgYVCgkICwIEFgIDAQIeAQIXgAAKCRCgScdloHyJ
2O8wAQCraDn4j3t2nbJdnQzOtriap2G6tLPMP/2KdyBuTsrb/wD+OK9SzuyAalIa
ORQPH2AFz+zitETbd3MlLVXCvFPeXwi4OARpaHcZEgorBgEEAZdVAQUBAQdAGSJe
15ZXCrl7pqA1abco8RGkWSjJyvLRXjK/OQbkAHwDAQgHiH4EGBYKACYWIQRN1bN5
F5jkk/ZJn42gScdloHyJ2AUCaWh3GQIbDAUJAO1OAAAKCRCgScdloHyJ2IEWAQCj
8Ft05mqxDTDgMpJ31VfHNwE/dYdKqNjVioBXLS8KBAEAq89bp35/abDycv81+WBh
4uCuZGpi5Lge2TZN+Zsiqww=
=YSLx
-----END PGP PUBLIC KEY BLOCK-----"""

# Colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    NC = '\033[0m'
    
    @classmethod
    def disable(cls):
        """Disable colors (for non-TTY output)"""
        cls.RED = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.BLUE = ''
        cls.NC = ''


@dataclass
class KeyInfo:
    """Information about a GPG key"""
    key_id: str
    fingerprint: str
    uid: str
    filepath: Optional[str] = None
    has_course_signature: bool = False
    is_course_key: bool = False


def run_gpg(args: list[str], homedir: Optional[str] = None, input_text: Optional[str] = None) -> subprocess.CompletedProcess:
    """Run a GPG command with optional custom homedir"""
    cmd = ["gpg"]
    if homedir:
        cmd += ["--homedir", homedir, "--batch", "--quiet"]
    cmd += args
    
    return subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True
    )


def parse_key_info(gpg_output: str) -> Optional[KeyInfo]:
    """Parse key info from gpg --list-keys --with-colons output"""
    key_id = None
    fingerprint = None
    uid = None
    
    for line in gpg_output.split("\n"):
        parts = line.split(":")
        if len(parts) < 2:
            continue
        
        if parts[0] == "pub" and key_id is None:
            key_id = parts[4] if len(parts) > 4 else None
        elif parts[0] == "fpr" and fingerprint is None:
            fingerprint = parts[9] if len(parts) > 9 else None
        elif parts[0] == "uid" and uid is None:
            uid = parts[9] if len(parts) > 9 else None
    
    if key_id and fingerprint:
        return KeyInfo(
            key_id=key_id,
            fingerprint=fingerprint,
            uid=uid or "",
            is_course_key=(fingerprint == COURSE_FINGERPRINT)
        )
    return None


def check_course_signature(gpg_output: str) -> bool:
    """
    Check if gpg --check-sigs output contains a valid course signature.
    
    Correctly handles multiple keys in the keyring by tracking which
    key block we're currently examining.
    """
    current_key_is_student = False
    
    for line in gpg_output.split("\n"):
        parts = line.split(":")
        if len(parts) < 2:
            continue
        
        record_type = parts[0]
        
        # "pub" starts a new key block
        if record_type == "pub" and len(parts) > 4:
            key_id = parts[4]
            current_key_is_student = (key_id != COURSE_LONG_ID)
        
        # Only check signatures on the student key
        if record_type == "sig" and current_key_is_student and len(parts) > 12:
            validity = parts[1]
            signer_key_id = parts[4]
            signer_fingerprint = parts[12]
            
            if signer_fingerprint == COURSE_FINGERPRINT or signer_key_id == COURSE_LONG_ID:
                return validity == "!"
    
    return False


def verify_key_file(keyfile_path: str) -> tuple[bool, str, Optional[KeyInfo]]:
    """
    Verify if a key file contains a signature from the course key.
    
    Uses a temporary keyring to avoid polluting the user's keyring.
    
    Returns:
        Tuple of (is_valid, message, key_info)
    """
    if not os.path.exists(keyfile_path):
        return False, f"File not found: {keyfile_path}", None
    
    if not keyfile_path.endswith(".asc"):
        return False, f"File extension must be .asc: {keyfile_path}", None
    
    tmpdir = tempfile.mkdtemp(prefix="gpg_verify_")
    
    try:
        # Import the key to check
        proc = run_gpg(["--import", keyfile_path], homedir=tmpdir)
        if proc.returncode != 0:
            return False, f"Failed to import key: {proc.stderr}", None
        
        # Get key info
        proc = run_gpg(["--list-keys", "--with-colons"], homedir=tmpdir)
        key_info = parse_key_info(proc.stdout)
        
        if not key_info:
            return False, "Could not parse key information", None
        
        key_info.filepath = keyfile_path
        
        if key_info.is_course_key:
            return False, "This is the course key itself", key_info
        
        # Import course key
        proc = run_gpg(["--import"], homedir=tmpdir, input_text=COURSE_PUBLIC_KEY)
        if proc.returncode != 0:
            return False, f"Failed to import course key: {proc.stderr}", None
        
        # Check signatures
        proc = run_gpg(["--check-sigs", "--with-colons"], homedir=tmpdir)
        
        key_info.has_course_signature = check_course_signature(proc.stdout)
        
        if key_info.has_course_signature:
            return True, "Key is signed by course key", key_info
        else:
            return False, "Key is NOT signed by course key", key_info
    
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def get_my_key_info() -> Optional[KeyInfo]:
    """Get information about the user's secret key"""
    proc = run_gpg(["--list-secret-keys", "--with-colons"])
    
    if proc.returncode != 0:
        return None
    
    key_id = None
    uid = None
    
    for line in proc.stdout.split("\n"):
        parts = line.split(":")
        if parts[0] == "sec" and key_id is None:
            key_id = parts[4] if len(parts) > 4 else None
        elif parts[0] == "uid" and uid is None:
            uid = parts[9] if len(parts) > 9 else None
    
    if key_id:
        # Get fingerprint
        proc = run_gpg(["--list-keys", "--with-colons", key_id])
        fingerprint = None
        for line in proc.stdout.split("\n"):
            parts = line.split(":")
            if parts[0] == "fpr":
                fingerprint = parts[9] if len(parts) > 9 else None
                break
        
        return KeyInfo(
            key_id=key_id,
            fingerprint=fingerprint or "",
            uid=uid or "",
            is_course_key=False
        )
    
    return None


def get_my_netid() -> Optional[str]:
    """
    Read NetID from .netid config file in repository root.
    
    Returns:
        NetID string if file exists and is valid, None otherwise.
    """
    netid_file = ".netid"
    
    if not os.path.exists(netid_file):
        return None
    
    try:
        with open(netid_file, "r") as f:
            netid = f.read().strip()
            return netid if netid else None
    except (IOError, OSError):
        return None


def sign_key(key_id: str) -> bool:
    """Sign a key with the user's secret key"""
    proc = run_gpg(["--batch", "--yes", "--sign-key", key_id])
    return proc.returncode == 0


def export_key(key_id: str, output_path: str) -> bool:
    """Export a public key to a file"""
    proc = run_gpg(["--export", "--armor", key_id])
    if proc.returncode == 0:
        with open(output_path, "w") as f:
            f.write(proc.stdout)
        return True
    return False


def import_key(keyfile_path: str) -> bool:
    """Import a key file into the user's keyring"""
    proc = run_gpg(["--import", keyfile_path])
    return proc.returncode == 0


def count_signatures(key_id: str) -> tuple[int, list[str]]:
    """
    Count non-self signatures on a key.
    
    Returns:
        Tuple of (count, list of signer UIDs)
    """
    proc = run_gpg(["--check-sigs", "--with-colons", key_id])
    
    signers = []
    current_key_id = None
    
    for line in proc.stdout.split("\n"):
        parts = line.split(":")
        if len(parts) < 2:
            continue
        
        if parts[0] == "pub":
            current_key_id = parts[4] if len(parts) > 4 else None
        
        if parts[0] == "sig" and len(parts) > 9:
            validity = parts[1]
            signer_key_id = parts[4]
            signer_uid = parts[9]
            
            # Skip self-signature and invalid signatures
            if signer_key_id != current_key_id and validity == "!":
                signers.append(signer_uid)
    
    return len(signers), signers


def ensure_course_key_imported() -> bool:
    """Make sure the course key is in the user's keyring"""
    proc = run_gpg(["--list-keys", COURSE_LONG_ID])
    if proc.returncode != 0:
        proc = run_gpg(["--import"], input_text=COURSE_PUBLIC_KEY)
        return proc.returncode == 0
    return True