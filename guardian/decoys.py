"""Decoys (canary tokens): things that look valuable and are never used legitimately, so any use is an alarm.

Guardian creates them; the admin places them (nothing is planted automatically). Each decoy has a random token in its
URL on Guardian. Kinds:
- link:  a URL to put in a document, wiki page or e-mail; opening it raises an alert.
- login: honey credentials (a fake admin portal URL, user and password) for a password file or script; any visit
         alerts, a sign-in attempt with the planted password is high severity. Submitted passwords are never stored.
- docx:  a Word document ("IT passwords") with a linked image that Word fetches from Guardian when it opens.
"""
import io
import secrets
import string
import zipfile
from xml.sax.saxutils import escape

KINDS = {"link": "Tracking link", "login": "Fake admin login", "docx": "Bait Word document"}
GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00"
       b"\x01\x00\x00\x02\x02D\x01\x00;")


def new(kind, label, site_id, by):
    pw = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(14)) + "!7"
    user = secrets.choice(["svc_backup", "adm_it", "admin.helpdesk", "sql_svc", "itadmin"])
    return {"id": secrets.token_hex(5), "token": secrets.token_urlsafe(18), "kind": kind, "label": label[:80], "site": site_id,
            "created_by": by, "user": user if kind in ("login", "docx") else None, "password": pw if kind in ("login", "docx") else None,
            "hits": [], "on": True}


def placement_text(d, url):
    """What the admin copies into the place where the decoy lives."""
    if d["kind"] == "link":
        return url
    return (f"Admin portal: {url}/login\nUser: {d['user']}\nPassword: {d['password']}\n")


def docx(d, url):
    """A small Word document with the honey credentials and a linked (not embedded) image Word fetches on open."""
    img = f"{url}/i.gif"
    body = "".join(f'<w:p><w:r><w:t xml:space="preserve">{escape(line)}</w:t></w:r></w:p>' for line in [
        "IT administration: accounts (confidential)", "", f"Admin portal: {url}/login", f"User: {d['user']}",
        f"Password: {d['password']}", "", "Do not share. Ask IT before changing."])
    pic = ('<w:p><w:r><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="9525" cy="9525"/>'
           '<wp:docPr id="1" name="logo"/><a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main">'
           '<a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture">'
           '<pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="1" name="logo"/>'
           '<pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:link="rIdImg"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill>'
           '<pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="9525" cy="9525"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom>'
           '</pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>')
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
           'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
           'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">'
           f'<w:body>{pic}{body}<w:sectPr/></w:body></w:document>')
    rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            f'<Relationship Id="rIdImg" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
            f'Target="{escape(img)}" TargetMode="External"/></Relationships>')
    types = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
             '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
             '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
             '<Default Extension="xml" ContentType="application/xml"/>'
             '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
             '</Types>')
    root = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/></Relationships>')
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", types)
        z.writestr("_rels/.rels", root)
        z.writestr("word/document.xml", doc)
        z.writestr("word/_rels/document.xml.rels", rels)
    return buf.getvalue()


LOGIN_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>Sign in</title><style>body{font:15px system-ui,sans-serif;background:#f3f4f6;margin:0}
form{max-width:340px;margin:12vh auto;background:#fff;padding:28px;border-radius:8px;box-shadow:0 1px 4px #0002}
input{width:100%;box-sizing:border-box;padding:9px;margin:6px 0 14px;border:1px solid #ccc;border-radius:4px}
button{width:100%;padding:10px;border:0;border-radius:4px;background:#1f4e8c;color:#fff}</style></head><body>
<form method="post" action="login"><h2>Administration</h2><label>User<input name="user" autocomplete="username"></label>
<label>Password<input name="password" type="password" autocomplete="current-password"></label><button>Sign in</button>
{msg}</form></body></html>"""
