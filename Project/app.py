from flask import Flask, redirect, url_for, render_template, request, session, flash
from pymongo import MongoClient
from flask_login import LoginManager, logout_user, login_user, current_user,UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta

import sqlite3

app = Flask(__name__)
app.secret_key = 'mysecretkey'

#database stuff
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
db = SQLAlchemy(app)

# set life of session
app.permanent_session_lifetime = timedelta(minutes=60)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(100))
    email = db.Column( db.String(100))


    def __int__(self, name, email):
        self._name = name
        self._email = email
        self._admin = False


@app.route('/')
def home():
    # index html file is called for homepage
    return render_template("index.html")

@app.route('/login')
def login():
    # login html file is called for login
    return render_template("login.html")

@app.route('/test')
def test():
    # test html file is called for a test page
    return render_template("test.html")


@app.route('/calendly')
def calendar():
    # calendly html file is called for homepage
    return render_template("calendly.html")

@app.route('/contact')
def contact():
    # test html file is called for contact
    return render_template("contact.html")

@app.route('/equipment')
def equipment():
    # login html file is called for login
    return render_template("equipment.html")

@app.route('/information')
def information():
    # login html file is called for login
    return render_template("information.html")

@app.route('/faq')
def faq():
    # test html file is called for about
    return render_template("faq.html")

@app.route('/signup')
def signup():
    # test html file is called for about
    return render_template("signup.html")

# local database
"""
@app.route('/signup', methods=['POST', 'GET'])
def signup_post():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']

    conn = sqlite3.connect('user.db')
    c = conn.cursor()
    c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
    conn.commit()

    # this will store local database contents in touple form
    c.execute("SELECT * FROM users")
    rows = c.fetchall()
    for row in rows:
        print(row)

    return redirect(url_for('login'))
"""


@app.route('/signup', methods=['POST', 'GET'])
def signup_post():
    # check to see if user already in DB
    # find users with that name, find first entry,
    found_user = Users.query.filter_by(name = user).first()
    if found_user:
        session["email"] = found_user.email
    else:
        #username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # pass username and leave name blank
        usr = Users(user, " ")
        db.session.add(usr)
        db.session.commit()





@app.route('/login', methods=['GET', 'POST'])
def login_post():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # query database for user information
        #conn = sqlite3.connect('user.db')
        #c = conn.cursor()
        #c.execute("SELECT id, username, password FROM users WHERE username = ? AND password = ?", (username, password))
        #user = c.fetchone()
        #conn.close()
        #if user:
        flash("You have logged in successfully! ")
            # create a session for the user and redirect to the home page
            #session['user_id'] = user[0]
            #session['username'] = user[1]
        session["user"] = username

        return redirect(url_for('user'))

        """else:
            # display an error message if login is unsuccessful
            error = "Invalid username or password"
            return render_template('login.html', error=error)"""
    else:
        # render the login page template for GET requests
        return redirect(url_for('login'))

@app.route("/user")
def user():
    if "user" in session:
        user = session["user"]
        return redirect(url_for("home"))



def init_db(): # initiates the local db (we'll replace this with a live db connection)
    conn = sqlite3.connect('user.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT,email TEXT,password TEXT)''')
    conn.commit()
    conn.close()



@app.route('/forgotPassword')
def forgotPassword():
    # index html file is called for homepage
    return render_template("forgotpassword.html")


# flash a messaged saying you have successfully logged out
# not completed
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for("home"))



init_db()


if __name__ == '__main__':
    db.create_all()
    # change host to ip4 address
    app.run(debug=True, host = '0.0.0.0', port=8000)
