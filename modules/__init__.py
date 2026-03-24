"""Reconnaissance modules registry."""

from modules import (
    basic_info,
    subdomain_enum,
    waf_detect,
    fingerprint,
    port_scan,
    directory_bruteforce,
    http_methods,
    cors_check,
    cookie_analysis,
    security_headers_check,
    email_security,
    wayback,
    cve_lookup,
)

ALL_MODULES = [
    basic_info,
    subdomain_enum,
    waf_detect,
    fingerprint,
    port_scan,
    directory_bruteforce,
    http_methods,
    cors_check,
    cookie_analysis,
    security_headers_check,
    email_security,
    wayback,
    cve_lookup,
]
