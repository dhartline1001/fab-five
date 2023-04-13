# Flask application for UT's Makerspace

from flask import Flask, redirect, url_for, render_template, request, session, flash, Blueprint, g
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_admin import Admin, BaseView, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_admin.menu import MenuLink
from flask_login import UserMixin, login_user, current_user, LoginManager, logout_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin.form import SecureForm


from twilio.rest import Client
import os



app = Flask(__name__)


# CHANGE BEFORE PRODUCTION
app.secret_key = 'mysecretkey'

# enter DB uri below
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///userv3.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Permanent sessions are stored in a cookie and are not deleted when the user closes their browser,
# while non-permanent sessions are deleted when the user closes their browser.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)


#login manager / access control
login_manager = LoginManager()
# enable user session protection
# helps prevent session fixation and session hijacking attacks
login_manager.session_protection = 'strong'
# set the duration for which a user will remain logged in.
login_manager.remember_cookie_duration = timedelta(days=14)

#redirect to login page if not logged in
login_manager.login_view="home"
login_manager.init_app(app)

from datetime import datetime, timedelta
from flask_login import current_user, logout_user



# Set up Twilio client with environment variables
"""twilio_account_sid = os.environ.get('TWILIO_ACCOUNT_SID')
twilio_auth_token = os.environ.get('TWILIO_AUTH_TOKEN')
twilio_phone_number = os.environ.get('TWILIO_PHONE_NUMBER')"""

twilio_account_sid = "ACdfef27e279ecec44cea806b8ab0f1409"
twilio_auth_token = "189059dfed60b822aeb8b564aaca32bb"
twilio_phone_number = "+18885232483"


client = Client(twilio_account_sid, twilio_auth_token)



#export TWILIO_ACCOUNT_SID="ACdfef27e279ecec44cea806b8ab0f1409"
#export TWILIO_AUTH_TOKEN="189059dfed60b822aeb8b564aaca32bb"
#export TWILIO_PHONE_NUMBER="+18885232483"

# This class creates navbar link back to homepage of application from admin page
class MainIndexLink(MenuLink):
    def get_url(self):
        return url_for("home")


#initialize database
with app.app_context():
    db = SQLAlchemy(app)

    # user model for database
    class User(db.Model, UserMixin):
        # Basic user info here
        id = db.Column(db.Integer, primary_key=True)
        first_name = db.Column(db.String(120), nullable=False)
        last_name = db.Column(db.String(120), nullable=False)
        username = db.Column(db.String(80), unique=True, nullable=False)
        email = db.Column(db.String(120), unique=True, nullable=False)
        student_id = db.Column(db.Integer, unique=True, nullable=False)
        password = db.Column(db.String(120), nullable=False)


        # add training here
        printer_3d = db.Column(db.Boolean, default=False)
        vinyl_cutter = db.Column(db.Boolean, default=False)
        heat_press = db.Column(db.Boolean, default=False)
        vacuum_former = db.Column(db.Boolean, default=False)
        cnc_machine = db.Column(db.Boolean, default=False)
        soldering_station = db.Column(db.Boolean, default=False)
        electronics_workstation = db.Column(db.Boolean, default=False)




        # admin / worker attributes
        is_admin = db.Column(db.Boolean, default=False)
        is_worker = db.Column(db.Boolean, default=False)



    # creates db entry for makerspace status
    class MakerspaceStatus(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        is_open = db.Column(db.Boolean, default=False)


    # create a new MakerspaceStatus object
    makerspace_status = MakerspaceStatus(is_open=False)

    # add the object to the database session.
    #db.session.add(makerspace_status)


    # commit the changes to the database
    db.session.commit()
    db.create_all()




# allows admin to edit users in DB
# Define a custom base view with admin permission
# only allow signed on admin to view admin DB page
class MyModelView(ModelView):
    form_base_class = SecureForm

    column_exclude_list = ['password']
    form_excluded_columns = ('password')  # exclude the password field
    column_searchable_list = ('last_name', 'first_name', 'email')

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('home'))

# enable admins to go to admin page
class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_admin

# adds worker view/ restricts access to setting worker/admin
class MyWorkerModelView(ModelView):
    column_searchable_list = ('last_name', 'first_name', 'email')
    # add db items workers are able to see
    form_base_class = SecureForm
    form_excluded_columns = ('password', 'is_admin', 'is_worker')  # set what to restrict in forms to be viewed by worker
    column_exclude_list = ['password']  # set items to restrict from columns

    # set read only values here for workers
    form_widget_args = {
        'email': {
            'readonly': True
        },
        'student_id': {
            'readonly': True
        }
    }

    def is_accessible(self):
        return current_user.is_authenticated and current_user.is_worker

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('home'))


# add main page link to db page, init admin page
admin = Admin(app, index_view=MyAdminIndexView(), template_mode='bootstrap4', name='UT Makerspace', base_template='admin/base.html')

# create admin and worker views
admin.add_view(MyModelView(User, db.session, endpoint='admin_view', category='Admin'))
admin.add_view(MyWorkerModelView(User, db.session, endpoint='worker_view', category='Worker'))
admin.add_link(MainIndexLink(name="Main Page"))
app.config['FLASK_ADMIN_FLUID_LAYOUT'] = True




# access user info to store id of logged-in user
@ login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# home page that passes makerspace open/close status
@app.route('/')
def home():
    makerspace_status = MakerspaceStatus.query.first()
    return render_template('index.html', is_open=makerspace_status.is_open)

# login route
@app.route('/login')
def login():
    # login html file is called for login
    return render_template("login.html")

# profile route / allows makerspace status to be changed
@app.route('/profile')
@login_required
def profile():
    # login html file is called for login
    makerspace_status = MakerspaceStatus.query.first()
    return render_template("profile.html", is_open=makerspace_status.is_open)


# route to change password in profile page
@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_new_password = request.form.get('confirm_new_password')

    # Get the user from the database
    user = User.query.filter_by(id=current_user.id).first()

    # Verify the old password
    if not check_password_hash(user.password, old_password):
        flash('Invalid old password. Please try again.', 'error')
        return redirect(url_for('profile'))

    # Verify the new password and confirm new password match
    if new_password != confirm_new_password:
        flash('New password and confirm new password must match. Please try again.', 'error')
        return redirect(url_for('profile'))

    # Generate a new password hash
    new_password_hash = generate_password_hash(new_password, method='sha256')

    # Update the user's password in the database
    user.password = new_password_hash
    db.session.commit()

    flash('Your password has been updated.', 'success')
    return redirect(url_for('profile'))

# updates makerspace status in database
@app.route('/profile/update_status', methods=['POST'])
@login_required
def update_status():
    # query for first instance of MS status
    makerspace_status = MakerspaceStatus.query.first()
    makerspace_status.is_open = (request.form['is_open'] == 'True')
    # commit status change to DB
    db.session.commit()
    return redirect(url_for('profile'))


# equipment page
@app.route('/equipment')
def equipment():
    # login html file is called for login
    return render_template("equipment.html")

# signup page
@app.route('/signup')
def signup():
    # test html file is called for about
    return render_template("signup.html")

# validates signup information and commits to db
@app.route('/signup', methods=['POST', 'GET'])
def signup_post():
    if request.method == 'POST':
        # get the form data
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        username = request.form['username']
        email = request.form['email']
        student_id = request.form['student_id']
        password = request.form['password']

        # check if a user with this email or username already exists
        existing_email = User.query.filter_by(email=email).first()
        existing_id = User.query.filter_by(student_id=student_id).first()
        existing_username = User.query.filter_by(username=username).first()
        if existing_email or existing_username or existing_id:
            # flash correct error message and render signup page again
            # this will consider duplicate email, username, or both
            if existing_username and existing_email:
                flash('Both Email and Username are already in use', category='error')
                return render_template('signup.html')
            elif existing_email:
                flash('Email address already in use', category='error')
                return render_template('signup.html')
            elif existing_id:
                flash('Student ID already in use', category='error')
                return render_template('signup.html')
            else:
                flash('Username already exists', category='error')
                return render_template('signup.html')


            # add password length field

        # create a new user
        user = User(first_name=firstName, last_name=lastName, username=username, email=email, student_id=student_id, password=generate_password_hash(password, method='sha256'))
        db.session.add(user)
        db.session.commit()
        flash('User created successfully')
        return redirect(url_for('login'))

    else:
        return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login_post():
    # query for user in db
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user:
            # check hashed password
            if check_password_hash(user.password, password):
                login_user(user, remember=True)
                # Make session permanent
                flash("Login Successful!")
                return redirect(url_for("home"))
            else:
                flash("Invalid email or password")
                return redirect(url_for("login"))
        else:
            flash("Invalid email or password")
            return redirect(url_for("login"))



# forgot password route
@app.route('/forgotPassword')
def forgotPassword():
    # index html file is called for homepage
    return render_template("forgotpassword.html")

@app.route('/emergency', methods=['GET', 'POST'])
def emergency():
    if request.method == 'POST':
        first_name = current_user.first_name  # Assuming this function returns a dictionary with 'first_name' and 'last_name' keys
        last_name = current_user.last_name

        phone_number = request.form['phone_number']
        message = f"{first_name} {last_name}: {request.form['message']}"

        # Send text message using Twilio API
        client.messages.create(
            body=message,
            from_=twilio_phone_number,
            to=phone_number
        )

        return redirect(url_for("emergency"))
    return render_template("emergency.html")

# pop user from session
# flash a messaged saying you have successfully logged out
# not completed
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have successfully logged out!")
    return redirect(url_for("home"))


if __name__ == '__main__':
    db.session.commit()
    # change host to ip4 address for mobile view
    app.run(debug=True, host = '0.0.0.0', port=8000)