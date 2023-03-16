from flask import Flask, redirect, url_for, render_template, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink

from flask_login import UserMixin, login_user, current_user

app = Flask(__name__)
app.secret_key = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///userv3.db'


# set life of session
app.permanent_session_lifetime = timedelta(minutes=60)

# This class creates navbar link back to homepage of application from admin page
class MainIndexLink(MenuLink):
    def get_url(self):
        return url_for("home")

# flask admin stuff
admin = Admin(app)
admin.add_link(MainIndexLink(name="Main Page"))

#initialize database
with app.app_context():
    db = SQLAlchemy(app)

    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        firstName = db.Column(db.String(120), nullable=False)
        lastName = db.Column(db.String(120), nullable=False)
        username = db.Column(db.String(80), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        password = db.Column(db.String(120), nullable=False)

        is_admin = db.Column(db.Boolean, default=False)
        is_worker = db.Column(db.Boolean, default=False)

        # TODO: set admin varaibles and add first/ last name once DB fixed

         # return string when access db
        def __repr__(self):
            return '<Name %r>' % self.id

    db.create_all()

# allows admin to edit users in DB
admin.add_view((ModelView(User, db.session)))
@app.route('/')
def home():
    # index html file is called for homepage

    return render_template("index.html")

@app.route('/login')
def login():
    # login html file is called for login

    return render_template("login.html")

@app.route('/people')
def people():
    # login html file is called for login

    return render_template("people.html")

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


@app.route('/signup', methods=['POST', 'GET'])
def signup_post():
    if request.method == 'POST':
        # get the form data
        # TODO: add admin/worker info
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # check if a user with this email already exists
        # if user already exists, do something else
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            # delete the existing user with this email
            flash('Email address already in use')
            return render_template('signup.html')

        # create a new user
        user = User(firstName=firstName, lastName=lastName, username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('User created successfully')
        return redirect(url_for('login'))

    else:
        return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login_post():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()

        if user:
            session['user_id'] = user.id
            session['is_admin'] = user.is_admin
            return redirect('/user')
        else:
            flash("Invalid email or password")
            return render_template('login.html')
    else:
        return render_template('login.html')


# retrieve the user from the database and render the dashboard template with the user's information
@app.route("/user")
def user():
    if 'user_id' in session:
        user_id = session['user_id']
        user = User.query.filter_by(id=user_id).first()
        flash("You have successfully logged in!")
        return render_template('index.html', user=user)

    else:
        return redirect('/')


@app.route('/forgotPassword')
def forgotPassword():
    # index html file is called for homepage
    return render_template("forgotpassword.html")


# flash a messaged saying you have successfully logged out
# not completed
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have successfully logged out!")
    return redirect(url_for("home"))



if __name__ == '__main__':
    # change host to ip4 address
    app.run(debug=True, host = '0.0.0.0', port=8000)
