"""Reconnaissance modules registry."""

from modules import (
    basic_info,
    subdomain_enum,
    fingerprint,
    port_scan,
    directory_bruteforce,
    security_headers_check,
    cve_lookup,
)

ALL_MODULES = [
    basic_info,
    subdomain_enum,
    fingerprint,
    port_scan,
    directory_bruteforce,
    security_headers_check,
    cve_lookup,
]
