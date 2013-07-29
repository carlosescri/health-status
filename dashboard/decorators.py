# -*- coding: utf-8 -*-

from flask import redirect, url_for

from dashboard.models import Setting


def check_configuration(view):
    """ Redirects to the setup if the app has not configured yet. """

    def wrapper(*args, **kwargs):
        username_setting = Setting.query.get('username')

        if username_setting is None:
            return redirect(url_for('InstallerView:index'))
        else:
            return view(*args, **kwargs)

    return wrapper
