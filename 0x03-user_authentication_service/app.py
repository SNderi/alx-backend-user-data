#!/usr/bin/env python3
"""A basic flask app for user authentication."""

from flask import Flask, jsonify, request, abort
from auth import Auth
from db import DB


app = Flask(__name__)


@app.route("/", methods=["GET"], strict_slashes=False)
def welcome():
    """Welcome message."""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def users():
    """An end-point to register a user."""
    email = request.form['email']
    password = request.form['password']
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login():
    """An end-point to help validate and login a user. """
    email = request.form['email']
    password = request.form['password']
    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        response = jsonify({"email": email, "message": "logged in"})
        response.set_cookie('session_id', session_id)
        return response
    else:
        abort(401)


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout():
    """An end-point to delete a user's session on logout. """
    session_id = request.cookies.get("session_id")
    try:
        user = AUTH.get_user_from_session_id(session_id)
        AUTH.destroy_session(user.id)
        return redirect("/")
    except Exception:
        abort(403)


@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile():
    """An end-point to handle display of profile information. """
    session_id = request.cookies.get("session_id")
    if not session_id:
        abort(403)
    try:
        user = AUTH.get_user_from_session_id(session_id)
        return jsonify({"email": "<user email>"}), 200
    except Exception:
        abort(403)


@app.route("/reset_password", methods=["POST"], strict_slashes=False)
def get_reset_password_token():
    """An end-point to handle password resetting token. """
    email = request.form['email']
    try:
        user = DB.find_user_by(email=email)
    except NoResultFound:
        abort(403)
    token = AUTH.get_reset_password_token(email)
    return jsonify({"email": email, "reset_token": token})


@app.route("/reset_password", methods=["POST"], strict_slashes=False)
def update_password():
    """An end-point to handle password update. """
    email = request.form['email']
    reset_token = request.form['reset_token']
    new_password = request.form['new_password']

    try:
        user = DB.find_user_by(email=email)
        if user.reset_token == reset_token:
            AUTH.update_password(reset_token, password)
    except Exception:
        abort(403)


AUTH = Auth()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
