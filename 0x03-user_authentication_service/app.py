#!/usr/bin/env python3
"""app.py modules"""
from flask import Flask, jsonify, request
from auth import Auth


Auth = Auth()

app = Flask(__name__)


@app.route("/", methods=["GET"])
def home():
    """defining the home route"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=["POST"])
def users() -> str:
    """users functio that implement the route for the users"""
    # get the data the user pass from the form
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        # register the user
        user = Auth.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"})
    except Exception:
        return jsonify({"message": "email already registered"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
