# -*- coding: utf-8 -*-

from flask import flash, redirect, request, url_for, abort, Response
from flask import render_template
from flask.ext.classy import FlaskView, route
from flask.ext.login import current_user, login_user, logout_user, \
    fresh_login_required

from dashboard import app, db
from dashboard.auth import User, Token
from dashboard.decorators import check_configuration
from dashboard.forms import LoginForm, CreateUserForm, RememberPasswordForm, \
    ResetPasswordForm, OAuthVerifierForm
from dashboard.models import Setting
from dashboard.utils import get_api, withings_oauth_init, \
    withings_oauth_verify, withings_get_measures


class RootView(FlaskView):
    route_base = '/'
    decorators = [check_configuration]

    def index(self):
        return render_template('index.html')

    @route('/withings/measures/<int:days>/<int:page>')
    def withings_measures(self, days, page):
        if days not in (5, 10, 15, 30, 60, 90) or page < 0:
            abort(404)

        response = Response(
            withings_get_measures(offset=page, days=days, to_json=True),
            status=200, mimetype='application/json')

        return response

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
            # create token and TODO: send by email
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
        ctxt = {
            'oauth_verifier_form': OAuthVerifierForm(),
        }

        # Get Withings config
        try:
            ctxt['withings'] = Setting.query.get('withings').value
        except AttributeError:
            ctxt['withings'] = withings_oauth_init().value

        return render_template('config/index.html', **ctxt)

    # Withings

    @route('/withings/oauth', methods=['POST'])
    def withings_oauth(self):
        msg = "Can't authorize Withings."

        try:
            form = OAuthVerifierForm()
            if form.validate_on_submit():
                cfg = withings_oauth_verify(form.data['oauth_verifier'])

                assert cfg.value.get('is_authenticated', False) == True
                msg = "Withings was authorized successfully."
        except (AttributeError, KeyError, AssertionError):
            pass

        flash(msg)
        return redirect(url_for('ConfigView:index'))

    @route('/reload/<path:path>')
    def reload_data(self, path):
        allowed = ('withings/user',)

        path = path.lower()

        if path not in allowed:
            abort(404)

        try:
            mod = path.split('/')[0]
            key = path.split('/')[1]

            api = get_api(mod)
            data = None

            if key == 'user':
                data = api.get_user()

            if data:
                setting = Setting.get_or_create(path.replace('/', '_'))
                setting.value = data
                db.session.commit()

            flash("The %s %s data was successfully reloaded." % (
                mod.capitalize(),
                key.capitalize()
            ))
        except AttributeError:
            flash("There was a problem reloading the %s %s data." % (
                mod.capitalize(),
                key.capitalize()
            ))

        return redirect(url_for('ConfigView:index'))

    # def twitter(self):
    #     return("TWITTER")

    # def tumblr(self):
    #     return "TUMBLR"

ConfigView.register(app)


@app.errorhandler(404)
def http404(e):
    return render_template('errors/404.html')
