#!/usr/bin/env python3
"""Implementing a custom authentication"""
import os
from flask import request
from typing import List, TypeVar
from models.user import User


class Auth:
    """class to manage basic api"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """a public methods"""
        if path is None:
            return True
        if excluded_paths is None or excluded_paths == []:
            return True
        # Normalize path by ensuring it ends with a slash
        # normal_path = path if path.endswith('/') else path + '/'

        # for excluded_path in excluded_paths:
            # n_excluded_path = (excluded_path if excluded_path.endswith('/')
            # else excluded_path + '/')
            # if normal_path == n_excluded_path:
            # return False
        # return True
        len_path = len(path)
        if len_path == 0:
            return True

        split_path = True if path[len_path - 1] == '/' else False

        temp_path = path
        if not split_path:
            temp_path += '/'
        for excluded_path in excluded_paths:
            len_exc = len(excluded_path)
            if len_exc == 0:
                continue

            if excluded_path[len_exc - 1] != '*':
                if temp_path == excluded_path:
                    return False
            else:
                if excluded_path[:-1] == path[:len_exc - 1]:
                    return False
        return True

    def authorization_header(self, request=None) -> str:
        """a public methods"""
        if request is None:
            return None
        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> TypeVar('User'):
        """ a public method"""
        return None

    def session_cookie(self, request=None):
        """Returns a cookie value from a request"""
        if request is None:
            return None

        session_name = os.getenv("SESSION_NAME")
        if session_name is None:
            return None

        return request.cookies.get(session_name)
