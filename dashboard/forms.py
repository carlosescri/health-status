# -*- coding: utf-8 -*-

import re

from babel.localedata import locale_identifiers
from pytz import common_timezones

from flask.ext.wtf import Form
from wtforms import TextField, PasswordField, SelectField, BooleanField, \
    validators

from dashboard import app, app_bcrypt
from dashboard.models import Setting

#
# User/Password related forms
#

class LoginForm(Form):
    username = TextField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])

    def validate(self):
        if not super(LoginForm, self).validate():
            return False

        username = Setting.query.get('username')
        password = Setting.query.get('password')

        if not (username and password) or username.value != self.username.data \
                or not app_bcrypt.check_password_hash(password.value,
                                                      self.password.data):
            if self._errors is None:
                self._errors = {}

            self._errors['global'] = "There is no user with those credentials."
            return False

        return True


class ResetPasswordForm(Form):
    password1 = PasswordField('Password', [
        validators.DataRequired(),
        validators.Length(min=8, max=50)
    ])
    password2 = PasswordField('Confirm Password', [
        validators.DataRequired(),
        validators.EqualTo('password1', "Enter the same password as above, for "
                                        "verification.")
    ])


class CreateUserForm(ResetPasswordForm):
    username = TextField('Username', [
        validators.DataRequired(),
        validators.Length(min=4, max=30),
        validators.Regexp(r'^[\w.@+-]+$', re.IGNORECASE,
                          "Letters, digits and '@', '.', '+', '-', '_' only.")
    ])
    email = TextField('Email', [
        validators.DataRequired(),
        validators.Email()
    ])


class RememberPasswordForm(Form):
    email = TextField('Email', [
        validators.DataRequired()
    ])

    def validate_email(self, field):
        # This is done to have only one error message.
        validator = validators.Email()
        validator(self, field)

        email_setting = Setting.query.get('email')
        if not email_setting or email_setting.value != field.data:
            raise validators.StopValidation('There is no user with that email.')


#
# OAuth related form
#

class OAuthVerifierForm(Form):
    oauth_verifier = TextField('OAuth Verifier', [validators.DataRequired()])


#
# Config related forms
#

class ConfigForm(Form):
    timezone = SelectField('Timezone',
                           default=app.config['BABEL_DEFAULT_TIMEZONE'],
                           choices=[(x, x) for x in common_timezones])
    locale = SelectField('Locale',
                         default=app.config['BABEL_DEFAULT_LOCALE'],
                         choices=[(x, x) for x in locale_identifiers()])
    sync_interval = SelectField('Sync Interval',
                                coerce=int,
                                default=1,
                                choices=[(x, '%d hours' % x) for x in range(1, 25)])
    show_name = BooleanField('Full Name is visible to all.', default=True)
    show_birthday = BooleanField('Birthday is visible to all.', default=True)
    show_gender = BooleanField('Gender is visible to all.', default=True)


class UninstallForm(Form):
    uninstall_word = TextField('Type "UNINSTALL" to reset the application.', [validators.DataRequired()])

    def validate_uninstall_word(self, field):
        if field.data != 'UNINSTALL':
            raise validators.StopValidation()
