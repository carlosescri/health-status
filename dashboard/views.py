# -*- coding: utf-8 -*-

import json

from flask import flash, redirect, request, url_for
from flask import render_template
from flask.ext.classy import FlaskView, route
from flask.ext.login import current_user, fresh_login_required, login_user, \
    logout_user

from dashboard import app, app_bcrypt, db
from dashboard.auth import User
from dashboard.decorators import check_configuration
from dashboard.forms import LoginForm, CreateUserForm
from dashboard.models import Setting


class RootView(FlaskView):
    route_base = '/'
    decorators = [check_configuration]

    def index(self):
        return render_template('index.html')

    @route('/login', methods=['GET', 'POST'])
    def login(self):
        if current_user.is_authenticated():
            return redirect(url_for('RootView:index'))

        form = LoginForm()
        if form.validate_on_submit():
            login_user(User(form.data['username']))

            if request.args.get('next'):
                return redirect(request.args.get('next'))

            return redirect(url_for('RootView:index'))

        return render_template('auth/login.html', form=form)

    @fresh_login_required
    def config(self):
        return render_template('config/index.html')

    def logout(self):
        logout_user()
        return redirect(url_for('RootView:index'))

RootView.register(app)


class InstallerView(FlaskView):
    route_base = '/install'

    @route('/', methods=['GET', 'POST'])
    def index(self):
        if not Setting.query.get('username') is None:
            return redirect(url_for('RootView:index'))

        form = CreateUserForm()
        if form.validate_on_submit():
            passwd = app_bcrypt.generate_password_hash(form.data['password1'])

            u = Setting(key='username', value=form.data['username'])
            p = Setting(key='password', value=passwd)

            db.session.add(u)
            db.session.add(p)
            db.session.commit()

            flash('Your user was created successfully.')

            login_user(User(form.data['username']))

            return redirect(url_for('RootView:config'))

        return render_template('installer/index.html', form=form)

InstallerView.register(app)


# class SettingsView(FlaskView):
#     decorators = [require_not_installed]

# SettingsView.register(app)


# http://www.withings.com/en/api
# class WithingsView(FlaskView):
#     def index(self):
#         return
