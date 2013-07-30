# -*- coding: utf-8 -*-

import re
import uuid

from flask.ext.login import UserMixin

from dashboard import app_bcrypt, db, login_manager
from dashboard.models import Setting


@login_manager.user_loader
def load_user(user_id):
    username = Setting.query.get('username')

    if not username or username.value != user_id:
        return None

    return User(user_id)


class User(UserMixin):
    def __init__(self, user_id, *args, **kwargs):
        super(User, self).__init__(*args, **kwargs)

        self.username = user_id
        self.email = Setting.query.get('email').value

    def get_id(self):
        return self.username

    @classmethod
    def set_password(cls, password):
        crypt_password = app_bcrypt.generate_password_hash(password)

        try:
            p = Setting.query.get('password')
            p.value = crypt_password
        except AttributeError:
            p = Setting(key='password', value=crypt_password)
            db.session.add(p)
        finally:
            db.session.commit()



class Token(object):
    @classmethod
    def create(cls):
        token = Setting(key='token', value=uuid.uuid4())
        db.session.add(token)
        db.session.commit()

        return token.value

    @classmethod
    def get(cls):
        try:
            return Setting.query.get('token').value
        except AttributeError:
            return None

    @classmethod
    def invalidate(cls):
        token = Setting.query.get('token')
        db.session.delete(token)
        db.session.commit()

    @classmethod
    def is_valid(cls, token):
        pattrn = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        return True if re.match(pattrn, token) and cls.get() == token else False
