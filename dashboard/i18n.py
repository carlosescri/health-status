# -*- coding: utf-8 -*-

from flask.ext.login import current_user

from dashboard import app_babel
from dashboard.utils import get_global_setting


@app_babel.timezoneselector
def get_timezone():
    if current_user.is_authenticated():
        return get_global_setting('timezone')
    return None
