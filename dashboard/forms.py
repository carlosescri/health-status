# -*- coding: utf-8 -*-

import re

from flask.ext.wtf import Form
from wtforms import TextField, PasswordField, validators

from dashboard import app_bcrypt
from dashboard.models import Setting


class LoginForm(Form):
    username = TextField('Username', [validators.Required()])
    password = PasswordField('Password', [validators.Required()])

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


class CreateUserForm(Form):
    username = TextField('Username', [
        validators.Required(),
        validators.Length(min=4, max=30),
        validators.Regexp(r'^[\w.@+-]+$', re.IGNORECASE,
                          "Letters, digits and '@', '.', '+', '-', '_' only.")
    ])
    password1 = PasswordField('Password', [
        validators.Required(),
        validators.Length(min=8, max=50)
    ])
    password2 = PasswordField('Confirm Password', [
        validators.Required(),
        validators.EqualTo('password1', "Enter the same password as above, for "
                                        "verification.")
    ])


class EditUserForm(CreateUserForm):
    password0 = PasswordField('Old Password', [
        validators.Required()
    ])
