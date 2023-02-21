#!/usr/bin/env python3
"""Module for a class SessionExpAuth that inherits from SessionAuth.
"""

import os
from datetime import datetime, timedelta
from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """Sets an expiration date to a Session ID.
    """
    def __init__(self):
        """Overloads the __init__ method."""
        try:
            duration = int(os.getenv('SESSION_DURATION'))
        except Exception:
            duration = 0
        self.session_duration = duration

    def create_session(self, user_id=None):
        """Creates a new session with start time set."""
        session_id = super().create_session(user_id)

        if not session_id:
            return None

        session_dictionary = {"user_id": user_id, "created_at": datetime.now()}
        self.user_id_by_session_id[session_id] = session_dictionary

        return session_id

    def user_id_for_session_id(self, session_id=None):
        """Returns a User ID based on a Session ID if the session time
        is still active.
        """
        if session_id is None:
            return None
        user_info = self.user_id_by_session_id.get(session_id)
        if user_info is None:
            return None
        if 'created_at' not in user_info:
            return None
        if self.session_duration <= 0:
            return user_info.get("user_id")
        created_at = user_info['created_at']
        limit = created_at + timedelta(seconds=self.session_duration)
        if limit < datetime.now():
            return None
        return user_info.get('user_id')
