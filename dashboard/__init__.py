# -*- coding: utf-8 -*-

import time

from flask import Flask
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


import dashboard.views

# Register template filters

@app.template_filter('strftime')
def tpl_filter_strftime(i_date, s_format='%Y-%m-%d'):
    return time.strftime(s_format, time.gmtime(i_date))
