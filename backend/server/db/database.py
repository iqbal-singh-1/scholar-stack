import sqlite3
import bcrypt
conn = sqlite3.connect("db/database.db", check_same_thread=False)
cursor = conn.cursor()

def insert_user(username, hashed_password, role):
    query = "INSERT INTO users (username, password, login_type) VALUES (?, ?, ?)"
    try:
        cursor.execute(query, (username, hashed_password, role))
        conn.commit()
        return True
    except Exception as e:
        print("Error inserting user:", e)
        return False

def check_user(username, password, role):
    conn = sqlite3.connect("db/database.db")
    cursor = conn.cursor()

    # Retrieve the hashed password from the database
    query = "SELECT password FROM users WHERE username = ? AND login_type = ?"
    cursor.execute(query, (username, role))
    result = cursor.fetchone()
    conn.close()

    if result:
        # Check the entered password against the stored hash
        stored_hashed_password = result[0]
        if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
            return True

    return False
    


def check_user_exists(username):
    conn = sqlite3.connect("db/database.db")
    cursor = conn.cursor()
    query = "SELECT username FROM users WHERE username = ?"
    try:
        cursor.execute(query, (username,))
        result = cursor.fetchone()
        conn.close()
        if result:
            return True
        return False
    except Exception as e:
        conn.close()
        return f"error: {str(e)}"


def get_user(username, role):
    query = "SELECT * FROM users WHERE username = ? AND login_type = ?"
    cursor.execute(query, (username, role))
    return cursor.fetchone()

def insert_upload_details(filename, file_type, file_size):
    query = "INSERT INTO uploads (filename, file_type, file_size) VALUES (?, ?, ?)"
    cursor.execute(query, (filename, file_type, file_size))
    conn.commit()

def get_all_uploads():
    query = "SELECT filename, file_type, file_size FROM uploads"
    cursor.execute(query)
    return cursor.fetchall()

import os

def delete_upload_details(filename):
    query = "DELETE FROM uploads WHERE filename = ?"
    cursor.execute(query, (filename,))
    conn.commit()

    uploads_folder = "uploads"
    file_path = os.path.join(uploads_folder, filename)

    if os.path.exists(file_path):
        try:
            os.remove(file_path)
            return True
        except Exception as e:
            return False
    else:
        return False


