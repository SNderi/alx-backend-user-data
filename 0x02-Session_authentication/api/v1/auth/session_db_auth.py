#!/usr/bin/env python3
"""Module for a new authentication class SessionDBAuth
that inherits from SessionExpAuth.
"""

from .session_exp_auth import SessionExpAuth
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    """A new authentication class"""
    def create_session(self, user_id=None):
        """Creates and stores new instance of UserSession
        and returns the Session ID
        """
        session_id = super().create_session(user_id)
        if not session_id:
            return None
        kwgs = {'user_id': user_id, 'session_id': session_id}
        user = UserSession(**kwgs)
        user.save()

        return session_id

    def user_id_for_session_id(self, session_id=None):
        """Returns the User ID by requesting UserSession
        in the database based on session_id
        """
        if session_id is None:
            return None
        user_id = UserSession.search({"session_id": session_id})
        if user_id:
            return user_id
        return None

    def destroy_session(self, request=None):
        """Destroys the UserSession based on the Session ID
        from the request cookie
        """
        if request is None:
            return False
        session_id = self.session_cookie(request)
        if not session_id:
            return False
        user_session = UserSession.search({"session_id": session_id})
        if user_session:
            user_session[0].remove()
            return True
        return False
