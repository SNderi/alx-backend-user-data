#!/usr/bin/env python3
"""A basic flask app for user authentication."""

from flask import Flask, jsonify, request
from auth import Auth


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


AUTH = Auth()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
