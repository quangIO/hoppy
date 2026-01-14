import os
import sqlite3


class User:
    def __init__(self, username=None, is_admin=False):
        self.username = username
        self.is_admin = is_admin

    def update(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


def get_db_connection():
    return sqlite3.connect("app.db")


def sanitize_input(data):
    # Imagine this is a real sanitizer
    return data.replace("'", "''")


def log_event(event):
    print(f"LOG: {event}")


def check_auth(user):
    if not user.is_admin:
        raise PermissionError("Not an admin")


# --- Scenarios ---


def vulnerability_1_sqli(request_data):
    """Classic SQLi: Taint from request_data to execute."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # BUG: Direct interpolation of request data
    query = f"SELECT * FROM users WHERE name = '{request_data}'"
    cursor.execute(query)
    return cursor.fetchall()


def vulnerability_2_path_traversal(user_path):
    """Path traversal: Taint from user_path to open."""
    base_dir = "/safe/dir"
    # BUG: No validation of user_path
    full_path = os.path.join(base_dir, user_path)
    with open(full_path) as f:
        return f.read()


def safe_1_with_sanitizer(request_data):
    """Safe because of sanitizer."""
    conn = get_db_connection()
    cursor = conn.cursor()
    clean_data = sanitize_input(request_data)
    query = f"SELECT * FROM users WHERE name = '{clean_data}'"
    cursor.execute(query)
    return cursor.fetchall()


def vulnerability_3_auth_bypass(user, command):
    """Logic bug: Sensitive operation without check_auth."""
    # BUG: missing check_auth(user)
    os.system(command)


def safe_2_with_auth(user, command):
    """Safe because of auth check."""
    check_auth(user)
    os.system(command)


def vulnerability_5_cmd_inj(user_input):
    """Generalized Command Injection."""
    import subprocess

    # Broad sink: subprocess.run
    subprocess.run(f"ls {user_input}", shell=True)


def safe_3_with_builtin_sanitizer(user_path):
    """Safe because it uses a standard-looking path sanitizer."""
    import os

    # Generalized sanitizer: os.path.basename
    clean_name = os.path.basename(user_path)
    with open(os.path.join("/tmp", clean_name)) as f:
        return f.read()


def vulnerability_6_indirect_sqli(data):
    """Indirect flow to execute."""
    conn = get_db_connection()
    # Taint flows through multiple variables
    sql = "SELECT " + data
    conn.execute(sql)


def vulnerability_7_unsafe_population(user_payload):
    """Mass assignment vulnerability."""
    user = User()
    # BUG: Directly populating user object from untrusted payload
    user.update(**user_payload)
    return user


def vulnerability_8_unsafe_population_dict(user_payload):
    """Mass assignment vulnerability with a dict."""
    user = User()
    # BUG: Directly populating user object from untrusted payload
    user.update(**user_payload)
    return user
