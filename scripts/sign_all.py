#!/usr/bin/env python3
"""
Sign all verified keys in the keys/ directory.
Usage:
    python sign_all.py [--dry-run]
    
Requires a .netid file in the repository root containing your NetID.
"""
import sys
import os
import glob
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from gpg_utils import (
    verify_key_file, get_my_key_info, get_my_netid,
    sign_key, export_key, import_key, ensure_course_key_imported,
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
        print("Make sure you have imported your private key.")
        sys.exit(1)
    
    print(f"Your NetID: {my_netid}")
    print(f"Your key: {my_key.key_id}")
    print(f"Your UID: {my_key.uid}")
    if dry_run:
        print(f"{Colors.YELLOW}[DRY RUN - no changes will be made]{Colors.NC}")
    print()
    
    # Ensure course key is imported
    ensure_course_key_imported()
    
    # Create output directory
    output_dir = f"signed/{my_netid}"
    if not dry_run:
        os.makedirs(output_dir, exist_ok=True)
    
    # Find all keys
    key_files = glob.glob("keys/*.asc")
    if not key_files:
        print("No key files found in keys/")
        sys.exit(0)
    
    signed_count = 0
    skipped_count = 0
    
    for keyfile in sorted(key_files):
        filename = os.path.basename(keyfile)
        print("-" * 40)
        print(f"Processing: {filename}")
        
        # Verify the key
        is_valid, message, key_info = verify_key_file(keyfile)
        
        if not key_info:
            print(f"  {Colors.YELLOW}⚠️  Could not parse key, skipping{Colors.NC}")
            skipped_count += 1
            continue
        
        # Skip course key
        if key_info.is_course_key:
            print(f"  {Colors.BLUE} Skipping course key{Colors.NC}")
            continue
        
        # Skip own key
        if key_info.key_id == my_key.key_id:
            print(f"  {Colors.BLUE} Skipping your own key{Colors.NC}")
            continue
        
        # Check course signature
        if not is_valid:
            print(f"  {Colors.RED} NOT signed by course key - skipping (possible adversarial key){Colors.NC}")
            skipped_count += 1
            continue
        
        print(f"  {Colors.GREEN} Verified course signature{Colors.NC}")
        
        if dry_run:
            print(f"  {Colors.YELLOW}🔏 Would sign and export to: {output_dir}/{filename}{Colors.NC}")
            signed_count += 1
            continue
        
        # Import the key to our keyring
        import_key(keyfile)
        
        # Sign the key
        print(f"  🔏 Signing...")
        if sign_key(key_info.key_id):
            # Export the signed key
            output_file = f"{output_dir}/{filename}"
            if export_key(key_info.key_id, output_file):
                print(f"  Exported to: {output_file}")
                signed_count += 1
            else:
                print(f"  {Colors.RED}❌ Failed to export{Colors.NC}")
                skipped_count += 1
        else:
            print(f"  {Colors.RED}❌ Failed to sign{Colors.NC}")
            skipped_count += 1
    
    print()
    print("=" * 40)
    print(f"Done! Signed {signed_count} keys, skipped {skipped_count}")
    if not dry_run:
        print(f"Signed keys are in: {output_dir}/")
        print()
        print("Next steps:")
        print(f"  1. git add signed/")
        print(f"  2. git commit -m 'Add signatures from {my_netid}'")
        print(f"  3. git push (or create PR)")
    print("=" * 40)
if __name__ == "__main__":
    main()