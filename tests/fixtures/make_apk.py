import io, struct, zipfile

def axml(strings):
    """Android binary XML containing just a UTF-16 string pool (what the inspector reads)."""
    enc = [struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00" for s in strings]
    offsets, pos = [], 0
    for e in enc:
        offsets.append(pos); pos += len(e)
    body = b"".join(struct.pack("<I", o) for o in offsets) + b"".join(enc)
    body += b"\x00" * (-len(body) % 4)
    hsize = 0x1C
    pool = struct.pack("<HHIIIIII", 0x0001, hsize, hsize + len(body), len(strings), 0, 0, hsize + 4 * len(strings), 0) + body
    return struct.pack("<HHI", 0x0003, 8, 8 + len(pool)) + pool

def make_apk(package, permissions, with_code=True):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", axml(["manifest", "package", package, "uses-permission", "name"] + permissions))
        if with_code:
            z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
        z.writestr("res/values/strings.xml", "<resources/>")
    return buf.getvalue()
