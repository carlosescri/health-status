# -*- coding: utf-8 -*-

import json

from withings import WithingsAuth, WithingsApi

from flask import flash, redirect, request, url_for, abort
from flask import render_template
from flask.ext.classy import FlaskView, route
from flask.ext.login import current_user, login_user, logout_user, \
    fresh_login_required

from dashboard import app, db
from dashboard.auth import User, Token
from dashboard.decorators import check_configuration
from dashboard.forms import LoginForm, CreateUserForm, RememberPasswordForm, \
    ResetPasswordForm
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

    def logout(self):
        logout_user()
        return redirect(url_for('RootView:index'))

    @route('/remember-password', methods=['GET', 'POST'])
    def remember_password(self):
        form = RememberPasswordForm()

        if form.validate_on_submit():
            # create token and send by email
            token = Token.create()

            flash("We've sent you an email with instructions on how to reset "
                  "your password.")
            return redirect(url_for('RootView:index'))

        return render_template('auth/remember_password.html', form=form)

    @route('/reset-password/<token>', methods=['GET', 'POST'])
    def reset_password(self, token):
        if not Token.is_valid(token):
            abort(404)

        form = ResetPasswordForm()

        if form.validate_on_submit():
            Token.invalidate()
            User.set_password(form.data['password1'])

            flash("Your password was saved successfully. You can login now.")
            return redirect(url_for('RootView:index'))

        return render_template('auth/reset_password.html', form=form)

RootView.register(app)


class InstallerView(FlaskView):
    route_base = '/install'

    @route('/', methods=['GET', 'POST'])
    def index(self):
        if not Setting.query.get('username') is None:
            return redirect(url_for('RootView:index'))

        form = CreateUserForm()
        if form.validate_on_submit():
            u = Setting(key='username', value=form.data['username'])
            e = Setting(key='email', value=form.data['email'])

            db.session.add(u)
            db.session.add(e)
            db.session.commit()

            User.set_password(form.data['password1'])

            login_user(User(form.data['username']))

            flash('Your user was created successfully.')
            return redirect(url_for('ConfigView:index'))

        return render_template('installer/index.html', form=form)

InstallerView.register(app)


class ConfigView(FlaskView):
    decorators = [check_configuration, fresh_login_required]

    def index(self):
        try:
            withings_config = json.loads(Setting.query.get('withings').value)
        except AttributeError:
            auth = WithingsAuth(app.config.get('WITHINGS_CONSUMER_KEY'),
                                app.config.get('WITHINGS_CONSUMER_SECRET'))
            withings_config = {'auth_url': auth.get_authorize_url()}

        return render_template('config/index.html', withings=withings_config)

    @route('/withings/auth', methods=['POST'])
    def withings_auth(self):
        return "WITHINGS: " + app.config.get('WITHINGS_CONSUMER_KEY')

    def twitter(self):
        return("TWITTER")

    def tumblr(self):
        return "TUMBLR"

ConfigView.register(app)


@app.errorhandler(404)
def http404(e):
    return render_template('errors/404.html')
