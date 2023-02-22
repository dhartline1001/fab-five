from flask import Flask, redirect, url_for, render_template, request, session, flash
from pymongo import MongoClient
import sqlite3

app = Flask(__name__)


# create app Pages
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

@app.route('/profile')
def profile():
    # profile html file is called for profile
    return render_template("profile.html")

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

@app.route('/signup', methods=['POST', 'GET'])
def signup_post():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']

    conn = sqlite3.connect('user.db')
    c = conn.cursor()
    c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", (username, email, password))
    conn.commit()
    #conn.close()

    # this will store local database contents in touple form
    c.execute("SELECT * FROM users")
    rows = c.fetchall()
    for row in rows:
        print(row)

    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login_post():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # query database for user information
        conn = sqlite3.connect('user.db')
        c = conn.cursor()
        c.execute("SELECT id, username, password FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        print("user:", user)
        conn.close()

        if user:
            # create a session for the user and redirect to the home page
            session['user_id'] = user[0]
            session['username'] = user[1]



            return redirect(url_for('homePage'))
        else:
            # display an error message if login is unsuccessful
            error = "Invalid username or password"
            return render_template('login.html', error=error)
    else:
        # render the login page template for GET requests
        return render_template('login.html')

def init_db(): # initiates the local db (we'll replace this with a live db connection)
    conn = sqlite3.connect('user.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT,
                  email TEXT,
                  password TEXT)''')
    conn.commit()
    conn.close()


@app.route('/home')
def home_welcome():
    if 'user_id' in session:
        # get user information from the session object and render the home page template
        user_id = session['user_id']
        username = session['username']

        print("Login successful")
        return render_template('homePage.html', username=username)
    else:
        # redirect to the login page if the user is not logged in
        return redirect(url_for('login'))

@app.route('/homePage')
def homePage():
    # index html file is called for homepage
    return render_template("homePage.html")

@app.route('/forgotPassword')
def forgotPassword():
    # index html file is called for homepage
    return render_template("forgotpassword.html")


# flash a messaged saying you have successfully logged out
# not completed
app.route('/logout')
def logout():
    session.pop("user", None)
    flash("You have been logged out")
    return redirect(url_for("index"))


init_db()
app.secret_key = 'mysecretkey'

if __name__ == '__main__':
    app.run(debug=True)
