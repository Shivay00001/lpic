"""
LPIC - Local-First Identity & Policy Core

A zero-cloud, SQLite-backed identity + policy + audit engine
that runs entirely locally.

Main exports:
- LPICEngine: Main engine class
- Keypair: Ed25519 keypair management
- Policy: Policy model
- SignedRequest: Signed authorization request
"""

from .engine import LPICEngine
from .identity_v2 import Keypair, SignedRequest, sign_request
from .policy import Policy
from .errors import *
from .config import *

__version__ = "0.1.0"

__all__ = [
    'LPICEngine',
    'Keypair',
    'SignedRequest',
    'sign_request',
    'Policy',
]
