from contextlib import contextmanager

import mysql.connector
from mysql.connector import Error

from config import Config


def get_connection():
    """
    Create and return a database connection for the configured backend.

    The connection uses manual transaction control so callers can
    explicitly commit or roll back related database operations together.
    """

    if Config.DATABASE_BACKEND == "supabase":
        import psycopg
        from psycopg.rows import dict_row

        try:
            return psycopg.connect(
                Config.SUPABASE_DB_URL,
                row_factory=dict_row,
                autocommit=False,
            )
        except psycopg.Error as exc:
            raise RuntimeError(
                "Supabase database connection failed. Check SUPABASE_DB_URL "
                "and ensure the database allows connections from this host."
            ) from exc

    try:
        connection = mysql.connector.connect(
            host=Config.MYSQL_HOST,
            port=Config.MYSQL_PORT,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DB,
            charset="utf8mb4",
            autocommit=False,
        )

        if not connection.is_connected():
            raise RuntimeError(
                "Unable to establish a MySQL database connection."
            )

        return connection

    except Error as exc:
        raise RuntimeError(
            "Database connection failed. "
            "Check MySQL service, credentials, and database configuration."
        ) from exc


@contextmanager
def get_db():
    """
    Provide a database connection with automatic transaction handling.

    Commits when the block completes successfully.
    Rolls back when an exception occurs.
    Always closes the connection.
    """

    connection = None

    try:
        connection = get_connection()
        yield connection
        connection.commit()

    except Exception:
        if connection and _connection_is_open(connection):
            connection.rollback()
        raise

    finally:
        if connection and _connection_is_open(connection):
            connection.close()


@contextmanager
def get_transaction():
    """
    Provide a database transaction for multiple related operations.

    All operations performed using the returned connection belong
    to the same transaction.

    The transaction is committed only when the context exits
    successfully. Any exception causes a rollback.
    """

    connection = None

    try:
        connection = get_connection()
        yield connection
        connection.commit()

    except Exception:
        if connection and _connection_is_open(connection):
            connection.rollback()
        raise

    finally:
        if connection and _connection_is_open(connection):
            connection.close()


def _connection_is_open(connection):
    """Handle the connection-state APIs used by both supported drivers."""
    if Config.DATABASE_BACKEND == "supabase":
        return not connection.closed
    return connection.is_connected()


def execute_query(
    query,
    params=None,
    fetchone=False,
    fetchall=False,
):
    """
    Execute a parameterized SQL query using its own transaction.

    Args:
        query: SQL query using %s placeholders.
        params: Query parameters.
        fetchone: Return one result row.
        fetchall: Return all result rows.

    Returns:
        Query results when requested, otherwise None.
    """

    with get_db() as connection:
        if Config.DATABASE_BACKEND == "supabase":
            cursor = connection.cursor()
        else:
            cursor = connection.cursor(dictionary=True)

        try:
            cursor.execute(query, params or ())

            if fetchone:
                return cursor.fetchone()

            if fetchall:
                return cursor.fetchall()

            return None

        finally:
            cursor.close()


def execute_insert(query, params=None):
    """
    Execute an INSERT query and return the generated row ID.
    """

    with get_db() as connection:
        cursor = connection.cursor()

        try:
            if Config.DATABASE_BACKEND == "supabase":
                cursor.execute(f"{query.rstrip().rstrip(';')} RETURNING id", params or ())
                return cursor.fetchone()["id"]

            cursor.execute(query, params or ())
            return cursor.lastrowid

        finally:
            cursor.close()


def execute_update(query, params=None):
    """
    Execute an UPDATE or DELETE query.

    Returns:
        Number of affected rows.
    """

    with get_db() as connection:
        cursor = connection.cursor()

        try:
            cursor.execute(query, params or ())
            return cursor.rowcount

        finally:
            cursor.close()


def execute_transaction_query(
    connection,
    query,
    params=None,
    fetchone=False,
    fetchall=False,
):
    """
    Execute a query using an existing transaction connection.

    This function is intended for workflows where several database
    operations must succeed or fail together.
    """

    if Config.DATABASE_BACKEND == "supabase":
        cursor = connection.cursor()
    else:
        cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(query, params or ())

        if fetchone:
            return cursor.fetchone()

        if fetchall:
            return cursor.fetchall()

        return None

    finally:
        cursor.close()


def execute_transaction_insert(
    connection,
    query,
    params=None,
):
    """
    Execute an INSERT using an existing transaction connection.

    Returns:
        Generated row ID.
    """

    cursor = connection.cursor()

    try:
        if Config.DATABASE_BACKEND == "supabase":
            cursor.execute(f"{query.rstrip().rstrip(';')} RETURNING id", params or ())
            return cursor.fetchone()["id"]

        cursor.execute(query, params or ())
        return cursor.lastrowid

    finally:
        cursor.close()


def execute_transaction_update(
    connection,
    query,
    params=None,
):
    """
    Execute an UPDATE or DELETE using an existing transaction connection.

    Returns:
        Number of affected rows.
    """

    cursor = connection.cursor()

    try:
        cursor.execute(query, params or ())
        return cursor.rowcount

    finally:
        cursor.close()