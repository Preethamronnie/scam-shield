"""Stage 4 of URL intelligence: where does the link really lead, and what does
the page do? Runs only when the user asks.

  1. The link is followed to its final page (redirects.fetch): HTTP redirects
     only, every hop checked so the server can't be pointed at internal
     addresses, at most 1 MB downloaded.
  2. If the "page" is actually an app or file download, that's reported.
  3. HTML is inspected statically inside the sandbox (inspectors.inspect_html):
     parsed as data, never rendered, scripts never run.
  4. The final address goes through stages 1-3 again, since it may differ
     completely from the link in the message.

Limits, stated honestly: pages that only reveal themselves when JavaScript
runs, or that show different content to different visitors (scam kits often
hide from automated checkers), may look harmless here. So, like the other
stages, finding nothing is "not verified", never "safe".
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import redirects, sandbox, urlintel
from .links import host_of


@dataclass
class DestinationReport:
    start_url: str
    final_url: str
    chain: list[dict]
    content_type: str = ""
    findings: list[dict] = field(default_factory=list)   # {level, text, id}
    facts: list[str] = field(default_factory=list)
    final_report: urlintel.UrlReport | None = None
    error: str = ""

    @property
    def verdict(self) -> str:
        levels = {f["level"] for f in self.findings}
        if self.final_report:
            levels |= {f.level for f in self.final_report.all_findings()}
        if "danger" in levels:
            return "Dangerous"
        if "warning" in levels:
            return "Suspicious"
        if self.final_report and self.final_report.verdict == "Official website" and not self.findings:
            return "Official website"
        return "Not verified"


def inspect_destination(url: str, online: bool = False) -> DestinationReport:
    page = redirects.fetch(url)
    rep = DestinationReport(url, page["final_url"], page["chain"], page["content_type"])
    if page["stopped"]:
        rep.facts.append(f"Stopped: {page['stopped']}.")
    if page["status"] is None:
        rep.error = page["stopped"] or "The page couldn't be reached."
        return rep

    if host_of(page["final_url"]) != host_of(url if "://" in url else "http://" + url):
        rep.facts.append(f"The link ends up at {host_of(page['final_url'])}.")
    rep.final_report = urlintel.analyse(page["final_url"], set(), online)

    ctype = page["content_type"].split(";")[0].strip().lower()
    disposition = page["disposition"].lower()
    if "android.package-archive" in ctype or ".apk" in disposition or page["final_url"].lower().split("?")[0].endswith(".apk"):
        rep.findings.append({"id": "dest_apk_download", "level": "danger",
                             "text": "The link downloads an Android app (.apk) directly. Don't install it."})
        return rep
    if "attachment" in disposition or (ctype and not ctype.startswith(("text/html", "application/xhtml"))):
        rep.facts.append(f"The link leads to a file ({ctype or 'unknown type'}), not a web page. It wasn't opened.")
        if ctype in ("application/x-msdownload", "application/x-msdos-program", "application/vnd.microsoft.portable-executable"):
            rep.findings.append({"id": "dest_program_download", "level": "danger",
                                 "text": "The link downloads a Windows program. Don't open it."})
        return rep
    if not page["body"]:
        rep.facts.append(f"The page returned no content (HTTP {page['status']}).")
        return rep
    try:
        found = sandbox.run_isolated("html", page["body"], arg=page["final_url"])
    except sandbox.SandboxError as e:
        rep.error = str(e)
        return rep
    rep.findings += [{"id": s["id"], "level": s["level"], "text": s["text"]} for s in found["signals"]]
    rep.facts += found["facts"]
    rep.facts.append("Pages can hide their real content from automated checks, so if nothing is found the page "
                     "is still only 'not verified'.")
    return rep
