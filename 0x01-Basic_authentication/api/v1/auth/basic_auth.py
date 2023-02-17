#!/usr/bin/env python3
""" Module for BasicAuth that inherits from Auth
"""

from api.v1.auth.auth import Auth
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """BasicAuth class that inherits from Auth.
    Methods: extract_base64_authorization_header
             decode_base64_authorization_header
             extract_user_credentials
             user_object_from_credentials
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        if authorization_header is None or not isinstance(
                authorization_header, str):
            return None
        elif authorization_header[:6] != "Basic ":
            return None
        else:
            return authorization_header[6:]

    def decode_base64_authorization_header(self, base64_authorization_header:
                                           str) -> str:
        """Returns the decoded value of a Base64 string.
        Args: base64_authorization_header
        """
        if base64_authorization_header is None or not isinstance(
                base64_authorization_header, str):
            return None
        else:
            import base64
            try:
                decoded = base64_authorization_header.encode('utf-8')
                decoded = base64.b64decode(decoded)
                return decoded.decode('utf-8')
            except Exception:
                return None

    def extract_user_credentials(self, decoded_base64_authorization_header:
                                 str) -> (str, str):
        """Returns the user email and password from the Base64 decoded value.
        """
        if decoded_base64_authorization_header is None:
            email, passwd = None, None
        elif not isinstance(decoded_base64_authorization_header, str):
            email, passwd = None, None
        elif ":" not in decoded_base64_authorization_header:
            email, passwd = None, None
        else:
            email = decoded_base64_authorization_header.split(":")[0]
            passwd = decoded_base64_authorization_header[len(email) + 1:]

        return (email, passwd)

    def user_object_from_credentials(self, user_email: str, user_pwd:
                                     str) -> TypeVar('User'):
        """Returns the User instance based on his email and password.
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        try:
            users = User.search({"email": user_email})
            if users is None or users == []:
                return None
            else:
                for user in users:
                    if user.is_valid_password(user_pwd):
                        return user
                return None
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """overloads Auth and retrieves the User instance for a request
        """
        auth_header = self.authorization_header(request)
        if auth_header is not None:
            token = self.extract_base64_authorization_header(auth_header)
            if token is not None:
                decoded = self.decode_base64_authorization_header(token)
                if decoded is not None:
                    email, passwd = self.extract_user_credentials(decoded)
                    if email is not None:
                        return self.user_object_from_credentials(email, passwd)
        return
