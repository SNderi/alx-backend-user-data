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

    def create_session(self, email: str) -> str:
        """Finds the user corresponding to the email,
        generates a new UUID and stores it in the database
        as the user’s session_id, then returns the session ID.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """It takes a single session_id string argument and
        returns the corresponding User or None.
        """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """It updates the corresponding user’s session ID to None. """
        try:
            self._db.update_user(user_id, session_id=None)
        except ValueError:
            return None
        return None

    def get_reset_password_token(self, email: str) -> str:
        """Generarates a UUID token to reset user password. """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """A function to change/update user password. """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError

        hashed_password = _hash_password(password)
        self._db.update_user(user.id, hashed_password=hashed_password,
                             reset_token=None)


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
