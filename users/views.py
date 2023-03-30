# IMPORTS
import logging
import bcrypt
import pyotp
from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from markupsafe import Markup
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime

from app import db, requires_roles
from models import User
from users.forms import RegisterForm, LoginForm

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        password=form.password.data,
                        role='user')

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Logs user registration.
        logging.warning('SECURITY - User registration [%s, %s]',
                        new_user.email,
                        request.remote_addr)

        # sends user to login page
        return redirect(url_for('users.login'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    # initialises users authentication attempts.
    if not session.get("authentication_attempts"):
        session["authentication_attempts"] = 0

    # Sets form to a LoginForm
    form = LoginForm()

    # Validates user login details and updates authentication attempts.
    if form.validate_on_submit():
        # Gets user username from DB
        user = User.query.filter_by(email=form.username.data).first()
        # Checks user exists, Checks pin, Checks password.
        if not user \
                or not bcrypt.checkpw(form.password.data.encode('utf-8'), user.password) \
                or not pyotp.TOTP(user.pinkey).verify(form.pin.data):
            # increases number of authentication attempts by user and logs
            logging.warning('SECURITY - Invalid Login attempt [%s, %s]',
                            user.email,
                            request.remote_addr)
            session["authentication_attempts"] += 1
            # Checks users authentication attempts allows password reset.
            if session.get("authentication_attempts") >= 3:
                flash(Markup('Number of incorrect login attempts exceeded '
                             'Please click <a href="/reset">here</a> to reset.'))
                # returns login page without form.
                return render_template('users/login.html')
            # informs user of authentication attempts.
            flash("Please check your login details and try again,"
                  " {} login attempts remaining".format(3 - session.get("authentication_attempts")))
            # returns login page
            return render_template('users/login.html', form=form)

        # Logs in user
        login_user(user)

        # Logs user logins
        logging.warning('SECURITY - Log in [%s, %s, %s]',
                        current_user.id,
                        current_user.email,
                        request.remote_addr)
        # Sets time of login
        user.last_login = user.current_login
        user.current_login = datetime.now()
        # Updates DB
        db.session.add(user)
        db.session.commit()
        # Checks user role
        if current_user.role == "admin":
            # returns admin page.
            return redirect(url_for('admin.admin'))
        else:
            # returns users profile page.
            return redirect(url_for('users.profile'))

    return render_template('users/login.html', form=form)


# view user profile
@users_blueprint.route('/profile')
@login_required
@requires_roles("user")
def profile():
    return render_template('users/profile.html', name=current_user.firstname)


# view user account
@users_blueprint.route('/account')
@login_required
@requires_roles("user", "admin")
def account():
    # sets the values on the account page to the current users details
    return render_template('users/account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone)


# Reset user password
@users_blueprint.route('/reset')
def reset():
    # resets number of authentication attempts
    session['authentication_attempts'] = 0

    return redirect(url_for('users.login'))


# Logs user out
@users_blueprint.route('/logout')
@login_required
@requires_roles("user", "admin")
def logout():

    # Logs user logouts
    logging.warning('SECURITY - Log out [%s, %s, %s]',
                    current_user.id,
                    current_user.email,
                    request.remote_addr)
    logout_user()

    return redirect(url_for('index'))
