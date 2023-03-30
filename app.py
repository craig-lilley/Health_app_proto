# IMPORTS
import os
import logging
from functools import wraps
from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_talisman import Talisman


# Logging filter
class Filter(logging.Filter):

    def filter(self, record):
        return 'SECURITY' in record.getMessage()


# Root Logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# File Handler
file_handler = logging.FileHandler('user.log', 'a')
file_handler.setLevel(logging.WARNING)

# Adding Filter to file handler
file_handler.addFilter(Filter())

# Create formatter.
formatter = logging.Formatter('%(asctime)s : %(message)s', '%m/%d/%Y %I:%M:%S %p')

# Adding formatter to file handler.
file_handler.setFormatter(formatter)

# Adding file handler to logger.
logger.addHandler(file_handler)

# CONFIG
app = Flask(__name__)
app.config['SECRET_KEY'] = 'LongAndRandomSecretKey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_ECHO'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config["RECAPTCHA_PUBLIC_KEY"] = os.getenv("RECAPTCHA_PUBLIC_KEY")
app.config["RECAPTCHA_PRIVATE_KEY"] = os.getenv("RECAPTCHA_PRIVATE_KEY")

# initialise database
db = SQLAlchemy(app)

# Adds security headers

csp = {
    'default-src': ['\'self\'',
                    'https://cdnjs.cloudflare.com/ajax/libs/bulma/0.7.2/css/bulma.min.css'],
    'frame-src': ['\'self\'',
                  'https://www.google.com/recaptcha/',
                  'https://recaptcha.google.com/recaptcha/'],
    'script-src': ['\'self\'',
                   '\'unsafe-inline\'',
                   'https://www.google.com/recaptcha/',
                   'https://www.gstatic.com/recaptcha/']
}
talisman = Talisman(app, content_security_policy=csp, force_https=False)


# RBAC Management
def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                # Logs invalid access attempts.
                logging.warning('SECURITY - Invalid access attempt [%s, %s, %s %s]',
                                current_user.id,
                                current_user.email,
                                current_user.role,
                                request.remote_addr)
                return render_template('errors/403.html')
            return f(*args, **kwargs)

        return wrapped

    return wrapper


# HOME PAGE VIEW
@app.route('/')
def index():
    return render_template('main/index.html')


# BLUEPRINTS
# import blueprints
from users.views import users_blueprint

#
# # register blueprints with app
app.register_blueprint(users_blueprint)


# Login Manager
login_manager = LoginManager()
login_manager.login_view = "users.login"
login_manager.init_app(app)

# User Loader
from models import User


# Gets user ID
@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


# Error Handling
@app.errorhandler(400)
def error403(error):
    return render_template("errors/400.html"), 400


@app.errorhandler(403)
def error403(error):
    return render_template("errors/403.html"), 403


@app.errorhandler(404)
def error404(error):
    return render_template("errors/404.html"), 404


@app.errorhandler(500)
def error500(error):
    return render_template("errors/500.html"), 500


@app.errorhandler(503)
def error403(error):
    return render_template("errors/503.html"), 503


# Runs app
if __name__ == "__main__":
    app.run()