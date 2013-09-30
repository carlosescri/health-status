# -*- coding: utf-8 -*-

from flask import flash, redirect, request, url_for, abort, Response
from flask import render_template
from flask.ext.babel import refresh as babel_refresh
from flask.ext.classy import FlaskView, route
from flask.ext.login import current_user, login_user, logout_user, \
    fresh_login_required

from dashboard import app, db
from dashboard.auth import User, Token
from dashboard.decorators import check_configuration
from dashboard.forms import LoginForm, CreateUserForm, RememberPasswordForm, \
    ResetPasswordForm, OAuthVerifierForm, ConfigForm, UninstallForm
from dashboard.models import BodyMeasure, Setting
from dashboard.utils import reload_config, withings_oauth_init, \
    withings_oauth_verify, withings_get_measures


class RootView(FlaskView):
    """ Main Controller """

    route_base = '/'
    decorators = [check_configuration]

    def index(self):
        return render_template('index.html')

    @route('/withings-measures/<int:days>/<int:page>')
    def withings_measures(self, days, page):
        """ Get measures from Withings cached data in JSON format.

        Args:
            - Number of days to get (5, 10, 15, 30, 60 or 90).
            - Number of page to get, starting on 1.
        """

        if days not in (5, 10, 15, 30, 60, 90) or page < 1:
            abort(404)

        offset = page - 1

        return Response(
            withings_get_measures(offset=offset, days=days, to_json=True),
            status=200,
            mimetype='application/json'
        )

    @route('/login', methods=['GET', 'POST'])
    def login(self):
        if current_user.is_authenticated():
            return redirect(url_for('RootView:index'))

        form = LoginForm()
        if form.validate_on_submit():
            login_user(User(form.data['username']))

            babel_refresh()

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
    """ App First Configuration """

    route_base = '/install'

    @route('/', methods=['GET', 'POST'])
    def index(self):
        db.create_all()

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
    """ App Configuration """

    decorators = [check_configuration, fresh_login_required]

    @route('/', methods=['GET', 'POST'])
    def index(self):
        withings_auth = withings_oauth_init()
        withings_user = Setting.get_or_create('withings_user')
        withings_sync = Setting.get_or_create('withings_sync')

        context = {
            'withings_auth': withings_auth.value,
            'withings_user': withings_user.value,
            'withings_sync': withings_sync.value,

            'uninstall_form': UninstallForm(),
        }

        if not withings_sync.value.get('is_authenticated', False):
            context['oauth_verifier_form'] = OAuthVerifierForm()

        config_form = ConfigForm(**(Setting.get_or_create('global').value))

        if config_form.validate_on_submit():
            global_setting = Setting.get_or_create('global')
            global_setting.value = config_form.data

            db.session.commit()
            babel_refresh()

            flash('Your settings were saved successfully.')
            return redirect(url_for('ConfigView:index'))

        context['config_form'] = config_form

        return render_template('config/index.html', **context)

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

                reload_config('withings', 'user')

        except (AttributeError, KeyError, AssertionError):
            pass

        flash(msg)
        return redirect(url_for('ConfigView:index'))

    @route('/withings/oauth/revoke')
    def withings_revoke_oauth(self):
        ws = Setting.query.get('withings_auth')
        if ws:
            db.session.delete(ws)
            db.session.commit()

        flash("OAuth credentials were successfully revoked.")
        return redirect(url_for('ConfigView:index'))

    @route('/uninstall', methods=['POST'])
    def uninstall(self):
        form = UninstallForm()
        if form.validate_on_submit():
            BodyMeasure.query.delete()
            Setting.query.delete()

            db.session.commit()
            logout_user()

            flash('The application was successfully reset.')

            return redirect(url_for('RootView:index'))
        else:
            flash('Please type "UNINSTALL" to reset the application.')
            return redirect(url_for('ConfigView:index'))

    @route('/reload/<path:path>')
    def reload_data(self, path):
        allowed = ()  # Ex: withings/user

        path = path.lower()

        if path not in allowed:
            abort(404)

        try:
            mod = path.split('/')[0]
            key = path.split('/')[1]

            reload_config(module=mod, key=key)

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
