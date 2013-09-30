# -*- coding: utf-8 -*-

import time

from dashboard import app


@app.template_filter('strftime')
def tpl_filter_strftime(i_date, s_format='%Y-%m-%d'):
    return time.strftime(s_format, time.gmtime(i_date))
