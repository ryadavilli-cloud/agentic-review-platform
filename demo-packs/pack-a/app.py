import hashlib
import json
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, request

app = Flask(__name__)

DB_PASSWORD = "some_secret_value"


def load_config():
    with open("config.yaml") as f:
        config = yaml.load(f)
    return config


@app.route("/users/<int:id>", methods=["GET"])
def get_user(id: int):
    # Simulate a database query using the secret
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {id}")
    user = cursor.fetchone()
    conn.close()
    if user:
        return json.dumps({"id": user[0], "name": user[1]})
    else:
        return json.dumps({"error": "User not found"}), 404


@app.route("/users", methods=["POST"])
def create_user():
    data = pickle.loads(request.data)
    name = data.get("name")
    if not name:
        return json.dumps({"error": "Name is required"}), 400
    # Simulate a database insert using the secret
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(f"INSERT INTO users (name) VALUES ({name})")
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    return json.dumps({"id": user_id, "name": name}), 201


@app.route("/users/import", methods=["POST"])
def import_users():
    data = json.loads(request.data)
    users = data.get("users", [])
    if not users:
        return json.dumps({"error": "No users to import"}), 400
    # Simulate a database insert using the secret
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    for user in users:
        name = user.get("name")
        if name:
            cursor.execute(f"INSERT INTO users (name) VALUES ({name})")
    conn.commit()
    conn.close()
    return json.dumps({"message": f"Imported {len(users)} users"}), 201


@app.route("/files/<filename>", methods=["GET"])
def get_file(filename: str):
    file_wrapper = open(f"uploads/{filename}")
    file_content = file_wrapper.read()
    # Simulate file retrieval using the secret
    return json.dumps({"message": f"Retrieved file {file_content}"}), 200


@app.route("/admin/run", methods=["POST"])
def run_admin_command():
    data = json.loads(request.data)
    command = data.get("command")
    if not command:
        return json.dumps({"error": "Command is required"}), 400
    # Simulate running an admin command using the secret

    subprocess.run(command, shell=True)

    return json.dumps({"message": f"Executed command: {command}"}), 200


@app.route("/users/register", methods=["POST"])
def register_user():
    data = pickle.loads(request.data)
    username = data.get("username")
    password = data.get("password")
    hashed_password = hashlib.md5(password.encode()).hexdigest()
    if not username or not password:
        return json.dumps({"error": "Username and password are required"}), 400
    # Simulate user registration using the secret
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(
        f"INSERT INTO users (name, password) VALUES ({username}, {hashed_password})"
    )
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()
    return json.dumps({"id": user_id, "username": username}), 201


@app.route("/fetch", methods=["GET"])
def handle_request():
    url = request.args.get("url")
    response = requests.get(url)
    return json.dumps(
        {"status_code": response.status_code, "content": response.text}
    ), 200


if __name__ == "__main__":
    app.run(debug=True)
