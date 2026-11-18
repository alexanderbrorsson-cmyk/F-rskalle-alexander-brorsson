import os
import re
import secrets
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        DATABASE=str(Path(__file__).with_name("forum.sqlite")),
    )
    if test_config:
        app.config.update(test_config)

    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)

    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DATABASE"])
            g.db.row_factory = sqlite3.Row
            g.db.execute("PRAGMA foreign_keys = ON")
        return g.db

    @app.teardown_appcontext
    def close_db(_error=None):
        database = g.pop("db", None)
        if database is not None:
            database.close()

    def init_db():
        database = get_db()
        database.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                password_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )
        database.commit()

    with app.app_context():
        init_db()

    @app.before_request
    def check_form_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        if request.method == "POST":
            submitted_token = request.form.get("csrf_token", "")
            if not secrets.compare_digest(session["csrf_token"], submitted_token):
                abort(400)

    def login_required(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Du måste logga in först.")
                return redirect(url_for("index"))
            return view(*args, **kwargs)

        return wrapped

    @app.route("/")
    def index():
        posts = get_db().execute(
            """
            SELECT posts.id, posts.message, posts.created_at, posts.user_id, users.username
            FROM posts
            JOIN users ON users.id = posts.user_id
            ORDER BY posts.id DESC
            """
        ).fetchall()
        return render_template("index.html", posts=posts)

    @app.route("/register", methods=["POST"])
    def register():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not re.fullmatch(r"[A-Za-z0-9_-]{3,30}", username):
            flash("Användarnamnet ska vara 3–30 tecken och bara innehålla bokstäver, siffror, _ eller -.")
        elif len(password) < 8:
            flash("Lösenordet måste innehålla minst 8 tecken.")
        else:
            database = get_db()
            try:
                cursor = database.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                database.commit()
            except sqlite3.IntegrityError:
                flash("Användarnamnet används redan.")
            else:
                session.clear()
                session["user_id"] = cursor.lastrowid
                session["username"] = username
                session["csrf_token"] = secrets.token_hex(32)
                return redirect(url_for("index"))

        return redirect(url_for("index"))

    @app.route("/login", methods=["POST"])
    def login():
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Fel användarnamn eller lösenord.")
            return redirect(url_for("index"))

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["csrf_token"] = secrets.token_hex(32)
        return redirect(url_for("index"))

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        session.clear()
        return redirect(url_for("index"))

    @app.route("/post", methods=["POST"])
    @login_required
    def create_post():
        message = request.form.get("message", "").strip()
        if not message or len(message) > 1000:
            flash("Inlägget måste innehålla 1–1000 tecken.")
            return redirect(url_for("index"))

        database = get_db()
        database.execute(
            "INSERT INTO posts (user_id, message) VALUES (?, ?)",
            (session["user_id"], message),
        )
        database.commit()
        return redirect(url_for("index"))

    @app.route("/post/<int:post_id>/delete", methods=["POST"])
    @login_required
    def delete_post(post_id):
        database = get_db()
        cursor = database.execute(
            "DELETE FROM posts WHERE id = ? AND user_id = ?",
            (post_id, session["user_id"]),
        )
        database.commit()

        if cursor.rowcount == 0:
            abort(404)

        flash("Inlägget togs bort.")
        return redirect(url_for("index"))

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
