"""Following a link's redirects, carefully, to show where it really leads.

Only done when the user asks, because:
  * contacting a scam link can tell the scammer it was opened (many links are
    unique per victim). The request comes from this server, not the user's
    phone, so it doesn't reveal the user's IP or device, but it can still
    mark the link as "clicked";
  * a server that fetches any URL a user types can be abused to reach
    internal services (SSRF). Every hop is checked: only http(s), standard
    ports, and only public IP addresses.

Only HTTP redirects are followed (HEAD requests, no page content is
downloaded and nothing is run), so pages that redirect with JavaScript will
stop at the first page.
"""
from __future__ import annotations

import ipaddress
import socket
import urllib.error
import urllib.request
from urllib.parse import urljoin, urlsplit

MAX_HOPS = 6
TIMEOUT = 4


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _public_host(host: str, port: int) -> bool:
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    for *_, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if not ip.is_global or ip.is_multicast:
            return False
    return True


def follow(url: str) -> list[dict]:
    """Returns the chain of addresses, e.g. [{"url": ..., "status": 301}, ..., {"url": ..., "status": 200}]."""
    if "://" in url and not url.lower().startswith(("http://", "https://")):
        return [{"url": url, "status": None, "stopped": "not a web address, not followed"}]
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    chain: list[dict] = []
    for _ in range(MAX_HOPS):
        parts = urlsplit(url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if parts.scheme not in ("http", "https") or port not in (80, 443, 8080, 8443):
            chain.append({"url": url, "status": None, "stopped": "unusual address, not followed"})
            break
        if not _public_host(parts.hostname or "", port):
            chain.append({"url": url, "status": None, "stopped": "doesn't point to a public website, not followed"})
            break
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "Mozilla/5.0 (link checker)"})
        try:
            resp = _OPENER.open(req, timeout=TIMEOUT)
            status, location = resp.status, None
            resp.close()
        except urllib.error.HTTPError as e:
            status, location = e.code, e.headers.get("Location")
        except Exception as e:
            chain.append({"url": url, "status": None, "stopped": f"couldn't connect ({type(e).__name__})"})
            break
        if status in (301, 302, 303, 307, 308) and location:
            chain.append({"url": url, "status": status})
            url = urljoin(url, location)
            continue
        chain.append({"url": url, "status": status})
        break
    else:
        chain.append({"url": url, "status": None, "stopped": "too many redirects"})
    return chain


MAX_PAGE_BYTES = 1024 * 1024


def fetch(url: str, max_bytes: int = MAX_PAGE_BYTES) -> dict:
    """Download a page for destination analysis, following redirects with the
    same safety checks as follow() on every hop. Reads at most max_bytes and
    returns the raw bytes for static analysis; nothing is rendered or run.

    Returns {"chain": [...], "final_url": str, "status": int|None,
             "content_type": str, "disposition": str, "body": bytes, "stopped": str}.
    """
    if "://" in url and not url.lower().startswith(("http://", "https://")):
        return {"chain": [{"url": url, "status": None}], "final_url": url, "status": None, "content_type": "",
                "disposition": "", "body": b"", "stopped": "not a web address, not followed"}
    if not url.lower().startswith(("http://", "https://")):
        url = "http://" + url
    chain: list[dict] = []
    for _ in range(MAX_HOPS):
        parts = urlsplit(url)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if parts.scheme not in ("http", "https") or port not in (80, 443, 8080, 8443):
            return _stop(chain, url, "unusual address, not followed")
        if not _public_host(parts.hostname or "", port):
            return _stop(chain, url, "doesn't point to a public website, not followed")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Linux; Android 14) link checker",
                                                   "Accept": "text/html,*/*;q=0.5"})
        try:
            resp = _OPENER.open(req, timeout=TIMEOUT)
        except urllib.error.HTTPError as e:
            location = e.headers.get("Location")
            if e.code in (301, 302, 303, 307, 308) and location:
                chain.append({"url": url, "status": e.code})
                url = urljoin(url, location)
                continue
            chain.append({"url": url, "status": e.code})
            return {"chain": chain, "final_url": url, "status": e.code, "content_type": "", "disposition": "",
                    "body": b"", "stopped": ""}
        except Exception as e:
            return _stop(chain, url, f"couldn't connect ({type(e).__name__})")
        with resp:
            body = resp.read(max_bytes + 1)
            chain.append({"url": url, "status": resp.status})
            return {"chain": chain, "final_url": url, "status": resp.status,
                    "content_type": resp.headers.get("Content-Type", ""),
                    "disposition": resp.headers.get("Content-Disposition", ""),
                    "body": body[:max_bytes], "stopped": "page larger than 1 MB, only the start was read"
                    if len(body) > max_bytes else ""}
    return _stop(chain, url, "too many redirects")


def _stop(chain, url, why):
    chain.append({"url": url, "status": None, "stopped": why})
    return {"chain": chain, "final_url": url, "status": None, "content_type": "", "disposition": "",
            "body": b"", "stopped": why}
