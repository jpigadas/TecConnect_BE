from flask import Flask
import os, logging
from config import app_config
from flask_cors import CORS

# from flask_sqlalchemy import SQLAlchemy
# from flask_migrate import Migrate
# from flask_marshmallow import Marshmallow
from logging.handlers import RotatingFileHandler

# # creates the Flask app
app = Flask(__name__)
CORS(app)

#app.register_blueprint(authn_blueprintz)
# export FLASK_ENV=development to run in dev mode
# get Environment or default to devellopment
env = os.environ.get('ENV', 'development')

#This config is needed if your URL can contain trailing slash. Example: This URL will not work http://localhost:3000/users/ if the below config is set to true
app.url_map.strict_slashes = False

# passing config 
print(" * Loading **" + env + "** environment")
app.config.from_object(app_config[env])




# for database connection using SQLAlchemy
# db = SQLAlchemy(app)
#
# # for creating db tables, updating db schema using migrate
# migrate = Migrate(app, db)
#
# # Using Marshmallow for returning DB schema as JSON in the API
# ma = Marshmallow(app)

# Logrotate will rotate log files if it exceeds certain size. And will backupCount retain last 5 logs. old backup log files will be deleted
# handler = RotatingFileHandler('app/log/development.log', maxBytes=1000000, backupCount=5)
# logger = logging.getLogger('db_service')
# logger.setLevel(logging.DEBUG)
#
# #format of the log, if you want to write log in a particular format. Comment below lines if you dont want this.
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s: %(message)s',datefmt='[%Y-%m-%dT%H:%M:%S]' )
# handler.setFormatter(formatter)
# logger.addHandler(handler)

#
# logging.basicConfig(filename="my_logs.log", level=logging.DEBUG)
# logger = logging.getLogger('my_logger')
# handler = RotatingFileHandler("my_logs.log", maxBytes=2000, backupCount=10)
# logger.addHandler(handler)

# Import the models, controllers, helpers.
from EnrollmentMS.app import controllers
from AuthenticationMS.app.controllers.tectango_rfid_routes import *
from token_validation import *