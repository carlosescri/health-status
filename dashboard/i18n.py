# -*- coding: utf-8 -*-

from flask.ext.login import current_user

from dashboard import app_babel
from dashboard.models import Setting


@app_babel.timezoneselector
def get_timezone():
    if current_user.is_authenticated():
        timezone = Setting.query.get('timezone')
        if timezone:
            return timezone

    return None
