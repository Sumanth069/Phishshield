"""
SSRF-Hardened URL Unshortener Module
- Follows HTTP redirects (bit.ly, t.co, tinyurl)
- Hardened against Server-Side Request Forgery (SSRF):
  Blocks private IP ranges (RFC 1918, loopback, AWS metadata 169.254.169.254)
- Enforces hard 5-hop limit and 2.5s timeout
- HEAD request with small byte-range GET fallback
"""

import ipaddress
import socket
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
import httpx

# Private IP subnets to block (SSRF protection)
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # RFC 1918 Private
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918 Private
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918 Private
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / AWS metadata
    ipaddress.ip_network("0.0.0.0/8"),         # Current network
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),          # IPv6 Unique Local
    ipaddress.ip_network("fe80::/10")          # IPv6 Link-Local
]

def is_private_or_blocked_ip(ip_str: str) -> bool:
    """Checks whether an IP address belongs to private, loopback, or metadata ranges."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in BLOCKED_IP_NETWORKS)
    except ValueError:
        return True # If not parseable, treat as unsafe

def resolve_hostname_ips(hostname: str) -> List[str]:
    """Resolves DNS hostname to list of IP addresses."""
    try:
        addrinfo = socket.getaddrinfo(hostname, None)
        return [item[4][0] for item in addrinfo]
    except Exception:
        return []

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "is.gd", "cutt.ly", "rebrand.ly", "tiny.cc", "rb.gy"
}

async def unshorten_url(url: str, max_hops: int = 5, timeout_sec: float = 2.5) -> Dict[str, Any]:
    """
    Asynchronously follows redirects on a shortened link with strict SSRF controls.
    """
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    current_url = url
    hops: List[str] = [current_url]
    ssrf_blocked = False

    headers = {
        "User-Agent": "PhishShield-Security-Scanner/1.0",
        "Range": "bytes=0-1024" # Small range to avoid downloading large payloads
    }

    async with httpx.AsyncClient(timeout=timeout_sec, verify=False) as client:
        for _ in range(max_hops):
            parsed = urlparse(current_url)
            hostname = parsed.hostname

            if not hostname:
                break

            # 1. SSRF Check: resolve hostname and verify all target IPs
            resolved_ips = resolve_hostname_ips(hostname)
            if not resolved_ips:
                # DNS failure or non-existent domain
                break

            for ip in resolved_ips:
                if is_private_or_blocked_ip(ip):
                    ssrf_blocked = True
                    return {
                        "original_url": url,
                        "final_url": current_url,
                        "hops": hops,
                        "hop_count": len(hops),
                        "is_shortened": len(hops) > 1,
                        "ssrf_blocked": True,
                        "blocked_ip": ip,
                        "error": f"Security Alert: Destination IP {ip} is within restricted private/internal network."
                    }

            # 2. Perform safe HEAD request first
            try:
                response = await client.head(current_url, headers=headers, follow_redirects=False)
                
                # If HEAD fails or is rejected (405 Method Not Allowed), fallback to small GET
                if response.status_code == 405:
                    response = await client.get(current_url, headers=headers, follow_redirects=False)

                # Check redirect headers
                if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location")
                    if not location:
                        break
                    
                    # Handle relative redirects
                    if location.startswith("/"):
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    
                    current_url = location
                    hops.append(current_url)
                else:
                    break # Reached final destination
            except Exception as e:
                # Timeout, network drop, or connection error
                break

    return {
        "original_url": url,
        "final_url": current_url,
        "hops": hops,
        "hop_count": len(hops),
        "is_shortened": len(hops) > 1,
        "ssrf_blocked": False,
        "error": None
    }
