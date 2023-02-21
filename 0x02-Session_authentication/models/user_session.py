#!/usr/bin/env python3
"""Module for a new authentication system,
based on Session ID stored in database.
"""

from models.base import Base


class UserSession(Base):
    """A new authentication system.
    """
    def __init__(self, *args: list, **kwargs: dict):
        """Initializes User session class
        Args: user_id: string
              session_id: string
        """
        super().__init__(*args, **kwargs)
        self.user_id = kwargs.get('user_id')
        self.session_id = kwargs.get('session_id')
