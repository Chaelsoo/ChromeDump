import uuid
from impacket import dpapi as idpapi
from Crypto.Cipher import PKCS1_v1_5


def load_pvk(pvk_path):
    with open(pvk_path, 'rb') as f:
        pvk_data = f.read()
    hdr = idpapi.PVK_FILE_HDR(pvk_data)
    assert hdr['dwMagic'] == 0xb0b5f11e, "Not a valid PVK file"
    blob_start = len(hdr) + hdr['cbEncryptData']
    priv_blob  = idpapi.PRIVATE_KEY_BLOB(pvk_data[blob_start:])
    rsa_key    = idpapi.privatekeyblob_to_pkcs1(priv_blob)
    return rsa_key, PKCS1_v1_5.new(rsa_key)


def decrypt_masterkey(mk_bytes, rsa_cipher):
    mkf = idpapi.MasterKeyFile(mk_bytes)
    if mkf['DomainKeyLen'] == 0:
        return None, None

    offset = (
        len(mkf)
        + int(mkf['MasterKeyLen'])
        + int(mkf['BackupKeyLen'])
        + int(mkf['CredHistLen'])
    )
    dk = idpapi.DomainKey(mk_bytes[offset:])

    # The ciphertext is stored in little-endian byte order per the MS-DPAPI spec
    sentinel  = b'\xff' * 32
    plaintext = rsa_cipher.decrypt(bytes(dk['SecretData'])[::-1], sentinel)
    if plaintext == sentinel:
        return None, None

    rsa_mk = idpapi.DPAPI_DOMAIN_RSA_MASTER_KEY(plaintext)
    masterkey = bytes(rsa_mk['buffer'])[:rsa_mk['cbMasterKey']]

    # The master key file name IS its GUID, used to match DPAPI blobs later
    guid_raw = bytes(mkf['Guid'])[:16]
    mk_guid  = str(uuid.UUID(bytes_le=guid_raw))

    return mk_guid, masterkey
