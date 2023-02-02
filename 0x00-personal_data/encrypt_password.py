#!/usr/bin/env python3
"""Module for password hashing using bcrypt.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """Returns a salted, hashed password, which is a byte string.
    """
    pass_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pass_bytes, salt)


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Validates that the provided password matches the hashed password.
    """
    pass_bytes = password.encode('utf-8')
    return bcrypt.checkpw(pass_bytes, hashed_password)
