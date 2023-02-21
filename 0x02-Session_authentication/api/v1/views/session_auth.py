#!/usr/bin/env python3
"""Module for a flask view that handles all routes for the
Session authentication.
"""

import os
from api.v1.views import app_views
from flask import request, jsonify
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def session_login():
    """Handles login for the Session authentication.
    """
    email = request.form.get('email')
    passwd = request.form.get('password')

    if email == '' or email is None:
        return jsonify({"error": "email missing"}), 400
    if passwd == '' or passwd is None:
        return jsonify({"error": "password missing"}), 400

    users = User.search({"email": email})
    if users is None or users == []:
        return jsonify({"error": "no user found for this email"}), 404
    else:
        for user in users:
            if user.is_valid_password(passwd):
                from api.v1.app import auth
                session_id = auth.create_session(user.id)
                response = jsonify(user.to_json())
                session_name = os.getenv('SESSION_NAME')
                response.set_cookie(session_name, session_id)
                return response
        return jsonify({"error": "wrong password"}), 401


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def session_logout():
    """Handles logout for the Session authentication.
    """
    from api.v1.app import auth
    resp = auth.destroy_session(request)
    if resp is False:
        abort(404)
    return jsonify({}), 200
