# -*- coding: utf-8 -*-

from flask.ext.login import UserMixin

from dashboard import login_manager
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

    def get_id(self):
        return self.username
