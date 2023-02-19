from flask import Flask, redirect, url_for, render_template, request
from pymongo import MongoClient

app = Flask(__name__)


# create app Pages
@app.route('/')
def home():
    # index html file is called for homepage
    return render_template("index.html")

@app.route('/login')
def login():
    # index html file is called for homepage
    return render_template("login.html")

@app.route('/test')
def test():
    # test html file is called for homepage
    return render_template("test.html")

@app.route('/profile')
def profile():
    # profile html file is called for homepage
    return render_template("profile.html")

@app.route('/calendly')
def calendar():
    # calendly html file is called for homepage
    return render_template("calendly.html")

@app.route('/contact')
def contact():
    # test html file is called for homepage
    return render_template("contact.html")

@app.route('/about')
def about():
    # test html file is called for homepage
    return render_template("about.html")

# past projects
#


if __name__ == '__main__':
    app.run(debug=True)
