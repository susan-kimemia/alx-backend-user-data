#!/usr/bin/env python3
"""Encrypting passwords"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    hash_password function that expects one string argument
    name password and returns a salted, hashed password, which
    is a byte string.Use the bcrypt package to perform the hashing
    (with hashpw).
    """
    # Generate a salt
    salt = bcrypt.gensalt()

    # Hashing the password with the generated salt
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    is_valid function that expects 2 arguments and returns a boolean.
    Arguments:
    hashed_password: bytes type
    password: string type
    Use bcrypt to validate that the provided
    password matches the hashed password.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
