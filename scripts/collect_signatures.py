#!/usr/bin/env python3
"""
Collect signatures on your key from the signed/ directory.
Usage:
    python collect_signatures.py [--dry-run]
    
Requires a .netid file in the repository root containing your NetID.
"""
import sys
import os
import glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gpg_utils import (
    get_my_key_info, get_my_netid, import_key, count_signatures,
    Colors, COURSE_LONG_ID
)
def main():
    dry_run = "--dry-run" in sys.argv
    
    if not sys.stdout.isatty():
        Colors.disable()
    
    # Get my NetID from config
    my_netid = get_my_netid()
    if not my_netid:
        print(f"{Colors.RED}Error: .netid file not found in repository root.{Colors.NC}")
        print("Create a .netid file containing your NetID:")
        print("  echo 'abc123' > .netid")
        sys.exit(1)
    
    # Get my key info
    my_key = get_my_key_info()
    if not my_key:
        print(f"{Colors.RED}Error: No secret key found.{Colors.NC}")
        sys.exit(1)
    
    print(f"Your NetID: {my_netid}")
    print(f"Your key: {my_key.key_id}")
    print(f"Your UID: {my_key.uid}")
    if dry_run:
        print(f"{Colors.YELLOW}[DRY RUN - no changes will be made]{Colors.NC}")
    print()
    
    # Count signatures before
    sig_count_before, signers_before = count_signatures(my_key.key_id)
    print(f"Signatures before: {sig_count_before}")
    print()
    
    # Find signed copies of our key
    pattern = f"signed/*/{my_netid}.asc"
    signed_files = glob.glob(pattern)
    
    if not signed_files:
        print(f"No signed copies found matching: {pattern}")
        print("Make sure others have signed your key and pushed to signed/<their-netid>/")
    
    imported_from = set()
    
    for signed_key in sorted(signed_files):
        signer_netid = os.path.basename(os.path.dirname(signed_key))
        
        if signer_netid in imported_from:
            continue
        
        if dry_run:
            print(f"{Colors.YELLOW}Would import signature from: {signer_netid}{Colors.NC}")
        else:
            print(f"Importing signature from: {signer_netid}")
            import_key(signed_key)
        
        imported_from.add(signer_netid)
    
    print()
    
    # Count signatures after
    if dry_run:
        sig_count_after = sig_count_before + len(imported_from)
        signers_after = signers_before
    else:
        sig_count_after, signers_after = count_signatures(my_key.key_id)
    
    print("=" * 40)
    print(f"Imported from {len(imported_from)} signers")
    print(f"Signatures before: {sig_count_before}")
    print(f"Signatures after:  {sig_count_after}")
    print(f"New signatures:    {sig_count_after - sig_count_before}")
    print("=" * 40)
    print()
    
    # List all signers
    print("Current signatures on your key:")
    for signer_uid in signers_after:
        if COURSE_LONG_ID in signer_uid or "CPSC4130" in signer_uid:
            print(f"  {Colors.GREEN}✅ CPSC4130 (course key){Colors.NC}")
        else:
            print(f"  {Colors.GREEN}✅ {signer_uid}{Colors.NC}")
    
    print()
    
    # Progress toward goal
    # Subtract 1 for course signature to get student count
    student_sigs = sig_count_after - 1
    if student_sigs >= 15:
        print(f"🎉 You have {student_sigs} student signatures (goal: 15) - {Colors.GREEN}COMPLETE!{Colors.NC}")
    else:
        print(f"📊 You have {student_sigs} student signatures (goal: 15) - need {15 - student_sigs} more")
if __name__ == "__main__":
    main()