#!/usr/bin/env python3
"""Hash password module"""
from user import User
from db import DB
from sqlalchemy.orm.exc import NoResultFound
import bcrypt
import uuid


def _hash_password(password: str) -> bytes:
    """
    method that takes in a password string arguments
    and returns bytes.
    The returned bytes is a salted hash of the input password,
    hashed with bcrypt.hashpw.
    """
    # Convert the password to bytes
    password_bytes = password.encode('utf-8')
    # Generate a salt
    salt = bcrypt.gensalt()

    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password


def _generate_uuid() -> str:
    """private function that return a string
    representation of a new UUID"""
    new_uuid = uuid.uuid4()
    return str(new_uuid)


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """This method register a user and if the user exist
        If a user already exist with the passed email, raise a ValueError.
        if email in self._db:
            raise ValueError(f"User {email} already exist")
        if no user using the email, hash the pass word and save it
        hash_password = self._hash_password(password)
        new_user = User(email, hash_password)
        self._db[email] = new_user
        return new_user
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            return self._db.add_user(email, _hash_password(password))
        else:
            raise ValueError(f"User {email} already exist")

    def valid_login(self, email: str, password: str) -> bool:
        """mplement the Auth.valid_login method. It should expect email and
        password required arguments and return a boolean.
        Try locating the user by email.
        If it exists, check the password with bcrypt.checkpw.
        If it matches return True.
        In any other case, return False."""
        try:
            # find the user in our database
            user = self._db.find_user_by(email=email)
            if user and bcrypt.checkpw(password.encode('utf-8'),
                                       user.hashed_password):
                return True
            else:
                return False
        except Exception:
            return False

    def create_session(self, email: str) -> str:
        """This method creates a session ID for the
        user identified by the email."""
        try:
            user = self._db.find_user_by(email=email)
            if user:
                session_id = _generate_uuid()
                self._db.update_user(user.id, session_id=session_id)
                return session_id
            else:
                return None
        except NoResultFound:
            return None
