# -*- coding: utf-8 -*-

from flask import Flask
from flask.ext.babel import Babel
from flask.ext.bcrypt import Bcrypt
from flask.ext.login import LoginManager
from flask.ext.sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config.from_pyfile('../cfg/settings.cfg')

db = SQLAlchemy(app)

app_bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'RootView:login'

app_babel = Babel(app)

import dashboard.i18n
import dashboard.templatetags
import dashboard.views
