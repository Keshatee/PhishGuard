"""Domain helpers."""

from dataclasses import dataclass

@dataclass(frozen=True)
class DomainParts:
    subdomain: str
    domain: str
    suffix: str

def extract(hostname: str) -> DomainParts:
    labels = [part for part in hostname.lower().strip('.').split('.') if part]
    if len(labels) < 2:
        return DomainParts('', labels[0] if labels else '', '')
    return DomainParts('.'.join(labels[:-2]), labels[-2], f'.{labels[-1]}')

def registered_domain(hostname: str) -> str:
    parts = extract(hostname)
    return f'{parts.domain}{parts.suffix}' if parts.domain and parts.suffix else ''
