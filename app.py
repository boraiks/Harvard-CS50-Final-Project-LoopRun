import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup

# Configure application
app = Flask(__name__)


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///looprun.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    if request.method == "GET":
        return render_template("index.html")


@app.route("/update_score", methods=["POST"])
def update_score():
    if request.method == "POST":
        newScore = int(request.form.get("score"))

        user_id = session["user_id"]

        currentHighScore = db.execute("SELECT score FROM users WHERE id = ?", user_id)
        highScore = currentHighScore[0]["score"]


        if newScore > highScore:
            db.execute("UPDATE users SET score = ? WHERE id = ?", newScore, user_id)
            return render_template("leaderboard.html")

        else:
            flash("Score updated successfully")
            return render_template("leaderboard.html")

        return render_template("leaderboard.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")



@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "GET":
        return render_template("register.html")

    if request.method == "POST":

        if not request.form.get("username"):
            return apology("Username can not be blank.")

        if not request.form.get("password"):
            return apology("Password can not be blank.")

        if not request.form.get("confirmation"):
            return apology("Confirmation can not be blank.")

        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords does not match.")

        newUser = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        if newUser:
            return apology("Username exists.")

        else:
            username = request.form.get("username")
            password = request.form.get("password")

            hash = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hash)
            return render_template("login.html")



@app.route("/change", methods=["GET", "POST"])
@login_required
def change_password():

    if request.method == "GET":
        return render_template("change.html")

    if request.method == "POST":

        user_id = session["user_id"]

        if request.form.get("confirmation") != request.form.get("confirmation2"):
            return apology("Passwords does not match.")

        if not request.form.get("password"):
            return apology("Password can not be blank.")

        if not request.form.get("confirmation"):
            return apology("Confirmation can not be blank.")

        else:
            result = db.execute("SELECT hash FROM users WHERE id = ?", user_id)
            current_password = request.form.get("password")
            stored_hash = result[0]['hash']
            if check_password_hash(stored_hash, current_password):
                new_password = request.form.get("confirmation")
                new_hash = generate_password_hash(new_password)
                db.execute("UPDATE users SET hash = ? WHERE id = ?", new_hash, user_id)

                flash("Success")

                return render_template("index.html")


@app.route("/leaderboard", methods=["GET", "POST"])
@login_required
def leaderboard():
    topTenScorers = db.execute("SELECT username, score FROM users ORDER BY score DESC LIMIT 10")
    return render_template("leaderboard.html", topScorers=topTenScorers)
