def make_pdf(lines, javascript=None, link=None, launch=False):
    """A small but valid PDF, built by hand, for tests."""
    stream = "BT /F1 14 Tf 50 750 Td 18 TL " + " ".join(f"({l}) '" for l in lines) + " ET"
    objs = ["<< /Type /Catalog /Pages 2 0 R" + (" /OpenAction 6 0 R" if javascript or launch else "") + " >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >>"
            + (" /Annots [7 0 R]" if link else "") + " >>",
            f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream",
            "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            (f"<< /S /JavaScript /JS ({javascript}) >>" if javascript else "<< /S /Launch /F (cmd.exe) >>") if (javascript or launch) else "<< >>",
            f"<< /Type /Annot /Subtype /Link /Rect [50 700 300 720] /A << /S /URI /URI ({link}) >> >>" if link else "<< >>"]
    out, offsets = b"%PDF-1.4\n", []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out)); out += f"{i} 0 obj\n{o}\nendobj\n".encode("latin-1")
    xref = len(out)
    out += f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode() + b"".join(f"{o:010d} 00000 n \n".encode() for o in offsets)
    out += f"trailer\n<< /Size {len(objs)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return out
