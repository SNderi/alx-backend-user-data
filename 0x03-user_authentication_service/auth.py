#!/usr/bin/env python3
"""Module for User Authentication.
"""

import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Verifys email uniqueness before registering a user in the
        database."""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                raise ValueError("User {} already exists".format(email))
        except NoResultFound:
            passwd = _hash_password(password)
            new_user = self._db.add_user(email=email, hashed_password=passwd)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Method for Credentials validation"""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False

        submitted_passwd = password.encode("utf-8")
        registered_passwd = user.hashed_password
        return bcrypt.checkpw(submitted_passwd, registered_passwd)


def _hash_password(password: str) -> bytes:
    """Returns a salted hash of the input password,
    hashed with bcrypt.hashpw.
    """
    passwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(passwd_bytes, salt)


def _generate_uuid() -> str:
    """A function that returns a string representation of a new UUID.
    """
    return str(uuid4())
