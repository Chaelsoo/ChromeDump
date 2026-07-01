import io
from impacket.smbconnection import SMBConnection


def connect(target, username, password, domain, lm_hash, nt_hash):
    smb = SMBConnection(target, target)
    smb.login(username, password, domain, lm_hash, nt_hash)
    return smb


def read_file(smb, share, path):
    buf = io.BytesIO()
    smb.getFile(share, path, buf.write)
    return buf.getvalue()


def list_dir(smb, share, path):
    try:
        entries = smb.listPath(share, path + r'\*')
        return [e.get_longname() for e in entries if e.get_longname() not in ('.', '..')]
    except Exception:
        return []
