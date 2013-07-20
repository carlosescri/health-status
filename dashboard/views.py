# -*- coding: utf-8 -*-

from random import choice

from flask.ext.classy import FlaskView, route

from dashboard import app, app_bcrypt, login_manager


class RootView(FlaskView):
    route_base = '/'

    def index(self):
        return ""


RootView.register(app)
