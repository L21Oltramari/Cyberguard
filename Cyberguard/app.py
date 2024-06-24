from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from helpers import login_required
from cs50 import SQL
import re

app = Flask(__name__)

# Configure Flask app
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Database setup
db = SQL("sqlite:///secure.db")

# Regular expressions for validation
pass_pat = re.compile(r"[A-Za-z0-9]+")
user_pat = re.compile(r"[A-Za-z0-9]+\_?[A-Za-z0-9]")

# Helper function to get user details
def get_user():
    user = "Account"
    if session.get("user_id"):
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if user:
            return user[0]
    return user

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Index route
@app.route("/")
def index():
    user = get_user()
    return render_template("index.html", nav=True, user=user)

# Routes requiring login
@app.route("/decryption")
@app.route("/encryption")
@app.route("/genPass")
@login_required
def secure_routes():
    user = get_user()
    return render_template(request.path[1:] + ".html", nav=True, user=user)

# Manager password route (GET and POST)
@app.route("/managerPass", methods=["GET", "POST"])
@login_required
def managerPass():
    user = get_user()
    if request.method == "GET":
        accounts = db.execute("SELECT * FROM passwords WHERE user_id = ?", session["user_id"])
        return render_template("managerPass.html", nav=True, accounts=accounts, user=user)
    else:
        accountName = request.form.get("name")
        accountPassword = request.form.get("password")
        accountLink = request.form.get("link")
        if not accountName or not accountPassword or not accountLink:
            return error("Required fields are missing.")
        db.execute("INSERT INTO passwords (user_id,name,link,password) VALUES (?,?,?,?);",
                   session["user_id"], accountName, accountLink, accountPassword)
        return redirect("/managerPass")

# Update password route
@app.route("/goupdate", methods=["GET", "POST"])
@login_required
def goUpdate():
    if request.method == "POST":
        id = request.form.get("id")
        account = db.execute("SELECT * FROM passwords WHERE user_id = ? AND id = ?", session["user_id"], id)
        if account:
            return render_template("update.html", account=account[0])
    return redirect("/managerPass")

@app.route("/update", methods=["POST"])
@login_required
def update():
    if request.method == "POST":
        id = request.form.get("id")
        name = request.form.get("name")
        password = request.form.get("password")
        link = request.form.get("link")
        if id and name and password and link:
            db.execute("UPDATE passwords SET name=?, password=?, link=? WHERE id=? AND user_id = ?;",
                       name, password, link, id, session["user_id"])
            return redirect("/managerPass")
    return error("Something went wrong.")

@app.route("/delete", methods=["POST"])
@login_required
def delete():
    if request.method == "POST":
        id = request.form.get("id")
        if id:
            db.execute("DELETE FROM passwords WHERE id = ?", id)
        return redirect("/managerPass")

# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            return error("Username and password are required.")
        elif not re.fullmatch(user_pat, username) or not re.fullmatch(pass_pat, password):
            return error("Invalid username or password format.")
        user = db.execute("SELECT * FROM users WHERE name = ?", username)
        if user and check_password_hash(user[0]["hash"], password):
            session["user_id"] = user[0]["id"]
            return redirect("/")
        return error("Invalid username or password.")
    return render_template("login.html")

# Logout route
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# Register route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        check = request.form.get("check")
        if not username or not password or password != check or not re.fullmatch(user_pat, username) or not re.fullmatch(pass_pat, password):
            return error("Invalid registration details.")
        existing_user = db.execute("SELECT name FROM users WHERE name = ?", username)
        if existing_user:
            return error("Username already exists.")
        hashed_password = generate_password_hash(password)
        db.execute("INSERT INTO users (name, hash) VALUES (?, ?)", username, hashed_password)
        user = db.execute("SELECT id FROM users WHERE name = ?", username)
        session["user_id"] = user[0]["id"]
        return redirect("/")
    return render_template("register.html")

# User account route
@app.route("/user")
@login_required
def user():
    user = get_user()
    if isinstance(user, dict):
        accounts = db.execute("SELECT * FROM passwords WHERE user_id = ?", session["user_id"])
        return render_template("user.html", nav=True, user=user, nbr=len(accounts))
    return render_template("user.html", nav=True, user=user, nbr=0)

# Delete account route
@app.route("/deleteAccount", methods=["POST"])
def deleteAccount():
    if request.method == "POST":
        db.execute("DELETE FROM passwords WHERE user_id = ?", session["user_id"])
        db.execute("DELETE FROM users WHERE id = ?", session["user_id"])
        session.clear()
    return redirect("/")

# Error route
def error(msg):
    return render_template("bad.html", msg=msg)

if __name__ == "__main__":
    app.run(debug=True)
