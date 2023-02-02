#!/usr/bin/env python3
"""Module for a function that obfuscates log messages.
"""

import os
import re
from typing import List
import logging
import mysql.connector


PII_FIELDS = ('name', 'email', 'phone', 'ssn', 'password')


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Redact the message of LogRecord instance"""
        message = super(RedactingFormatter, self).format(record)
        redacted = filter_datum(self.fields, self.REDACTION,
                                message, self.SEPARATOR)
        return redacted


def get_logger() -> logging.Logger:
    """Returns a logging.Logger object.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    s_handler = logging.StreamHandler()

    s_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(s_handler)

    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """ Returns a connector to the database
    """
    user_name = os.getenv("PERSONAL_DATA_DB_USERNAME", default="root")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", default="")
    host = os.getenv("PERSONAL_DATA_DB_HOST", default="localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME")

    mydb = mysql.connector.connect(host=host,
                                   user=user_name,
                                   password=password,
                                   database=db_name
                                   )
    return mydb


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """A function that returns the log message obfuscated.
    Args: fields (list): list of strings indicating fields to obfuscate
          redaction (str): what the field will be obfuscated to
          message (str): the log line to obfuscate
          separator (str): the character separating the fields
    """
    for field in fields:
        message = re.sub(field+'=.*?'+separator,
                         field+'='+redaction+separator, message)
    return message


def main():
    """
    main entry point
    """
    db = get_db()
    logger = get_logger()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    fields = cursor.column_names
    for row in cursor:
        message = "".join("{}={}; ".format(k, v) for k, v in zip(fields, row))
        logger.info(message.strip())
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
