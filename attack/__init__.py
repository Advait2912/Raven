# Assessment and attack modules for RAVEN.

from .base import AttackModule

__all__ = [
    "AttackModule",
    "CORSMisconfigurationModule",
    "ExcessiveDataExposureModule",
    "IDORAttack",
    "InformationDisclosureModule",
    "SecurityHeadersModule",
    "TechnologyFingerprintModule",
]


def __getattr__(name: str):
    if name == "IDORAttack":
        from .idor import IDORAttack
        return IDORAttack
    if name == "SecurityHeadersModule":
        from .headers import SecurityHeadersModule
        return SecurityHeadersModule
    if name == "InformationDisclosureModule":
        from .disclosure import InformationDisclosureModule
        return InformationDisclosureModule
    if name == "TechnologyFingerprintModule":
        from .fingerprint import TechnologyFingerprintModule
        return TechnologyFingerprintModule
    if name == "CORSMisconfigurationModule":
        from .cors import CORSMisconfigurationModule
        return CORSMisconfigurationModule
    if name == "ExcessiveDataExposureModule":
        from .exposure import ExcessiveDataExposureModule
        return ExcessiveDataExposureModule
    raise AttributeError(f"module 'attack' has no attribute '{name}'")
