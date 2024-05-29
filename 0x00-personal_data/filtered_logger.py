#!/usr/bin/env python3
"""
Write a function called filter_datum that returns the log message
obfuscated:
Arguments:
fields: a list of strings representing all fields to obfuscate
redaction: a string representing by what the field will be obfuscated
message: a string representing the log line
separator: a string representing by which character is separating all
fields in the log line (message)
The function should use a regex to replace occurrences of certain field
values.
filter_datum should be less than 5 lines long and use re.sub to perform
the substitution with a single regex.
"""
import os
import re
import logging
import mysql.connector
from typing import List

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """Function to anonymize sensitive information in log files."""
    escaped_fields = '|'.join(re.escape(f) for f in fields)
    pattern = f"({escaped_fields})=([^ {re.escape(separator)}]+)"
    return re.sub(pattern, lambda m: f"{m.group(1)}={redaction}", message)


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class"""
    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Mtd to filter values in incoming log records using filter_datum."""
        original_message = record.msg
        redacted_message = filter_datum(self.fields,
                                        self.REDACTION,
                                        original_message, self.SEPARATOR)
        record.msg = redacted_message
        return super(RedactingFormatter, self).format(record)


def get_logger() -> logging.Logger:
    """
    function that takes no arguments
    and returns a logging.Logger object
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # not to propogate

    # creating a streamhandler to be able to store in file we want
    stream_handler = logging.StreamHandler()
    # create and set the formatter
    formatter = RedactingFormatter(PII_FIELDS)
    stream_handler.setFormatter(formatter)

    # add the handler to the logger
    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    connect to a secure holberton database to read a users table.
    The database is protected by a username and password that are
    set as environment variables on the server named
    PERSONAL_DATA_DB_USERNAME (set the default as “root”),
    PERSONAL_DATA_DB_PASSWORD (set the default as
    an empty string) and PERSONAL_DATA_DB_HOST (set the default
    as “localhost”).The database name is stored in PERSONAL_DATA_DB_NAME.
    """
    user = os.getenv('PERSONAL_DATA_DB_USERNAME') or "root"
    passwd = os.getenv('PERSONAL_DATA_DB_PASSWORD') or ""
    host = os.getenv('PERSONAL_DATA_DB_HOST') or "localhost"
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')
    conn = mysql.connector.connect(user=user,
                                   password=passwd,
                                   host=host,
                                   database=db_name)
    return conn


def main():
    """
    The function will obtain a database connection using get_db and
    retrieve all rows in the users table and display each row under a
    filtered format
    """
    logger = get_logger

    # connecting to database
    db_conn = get_db()
    cursor = db_conn.curesor(dictionary=True)
    # performing the query
    cursor.execute("SELECT * FROM users")

    # retrieving and logging each row
    for row in cursor:
        message = "; ".join(f"{key}={value}" for key, value in row.items())
        logger.info(message)

    # close the cursor and connection
    cursor.close()
    db_conn.close()


if __name__ == "__main__":
    main()
