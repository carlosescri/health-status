# -*- coding: utf-8 -*-

from flask import Flask
from flask.ext.bcrypt import Bcrypt
from flask.ext.login import LoginManager

app = Flask(__name__)
app.config.from_pyfile('../cfg/settings.cfg')

app_bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)

import dashboard.views
