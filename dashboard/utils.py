# -*- coding: utf-8 -*-

import simplejson as json
import time

from calendar import timegm
from datetime import date, datetime
from dateutil import rrule
from dateutil.relativedelta import relativedelta
from withings import *

from dashboard import app, db
from dashboard.const import WITHINGS_GENDER_MALE, WITHINGS_CATEGORY_MEASURE, \
    WITHINGS_ATTRIBUTION_USER
from dashboard.models import BodyMeasure, Setting


#
# Global
#

def get_api(name):
    if name == 'withings':
        return _get_withings_api_obj()

    return None

def datetime_to_epoch(dt):
    return int(time.mktime(dt.timetuple()))

def epoch_to_datetime(epoch):
    return datetime.fromtimestamp(epoch)

def reload_config(module, key):
    api = get_api(module)
    data = None

    if key == 'user':
        data = api.get_user()['users'][0]
        data['gender'] = 'male' if data['gender'] == WITHINGS_GENDER_MALE else 'female'
        #data['birthdate'] = time.strftime('%Y-%m-%d', time.gmtime(data['birthdate']))


    if data:
        setting = Setting.get_or_create("%s_%s" % (module, key))
        setting.value = data
        db.session.commit()



#
# Withings
#

def _get_withings_api_obj():
    try:
        ws = Setting.query.get('withings_auth').value

        if ws.get('is_authenticated', False):
            consumer_key = app.config.get('WITHINGS_CONSUMER_KEY')
            consumer_secret=app.config.get('WITHINGS_CONSUMER_SECRET')

            credentials = WithingsCredentials(
                access_token=ws['access_token'],
                access_token_secret=ws['access_token_secret'],
                consumer_key=consumer_key,
                consumer_secret=consumer_secret,
                user_id=ws['user_id']
            )

            return WithingsApi(credentials)
    except AttributeError:
        pass

    return None


def withings_oauth_init():
    ws = Setting.get_or_create('withings_auth')

    if not ws.value.get('is_authenticated', False):

        auth = WithingsAuth(app.config.get('WITHINGS_CONSUMER_KEY'),
                            app.config.get('WITHINGS_CONSUMER_SECRET'))
        auth_url = auth.get_authorize_url()

        ws.value = {
            'is_authenticated': False,
            'oauth_token': auth.oauth_token,
            'oauth_secret': auth.oauth_secret,
            'auth_url': auth_url
        }

        db.session.commit()

    return ws


def withings_oauth_verify(oauth_verifier):
    """ Verify OAUTH credentials """

    ws = Setting.get_or_create('withings_auth')

    ws.value['oauth_verifier'] = oauth_verifier.strip()

    assert ws in db.session.dirty

    auth = WithingsAuth(app.config.get('WITHINGS_CONSUMER_KEY'),
                        app.config.get('WITHINGS_CONSUMER_SECRET'))

    auth.oauth_token = ws.value['oauth_token']
    auth.oauth_secret = ws.value['oauth_secret']

    credentials = auth.get_credentials(ws.value['oauth_verifier'])
    credentials = credentials.__dict__

    del credentials['consumer_key']
    del credentials['consumer_secret']
    del ws.value['auth_url']

    ws.value.update(credentials)
    ws.value['is_authenticated'] = True

    db.session.commit()

    return ws


def withings_sync():
    api = _get_withings_api_obj()
    ws = Setting.get_or_create('withings_sync', value={})

    try:
        measures = api.get_measures(lastupdate=ws.value['lastupdate'])
    except (TypeError, KeyError):
        measures = api.get_measures()

    for measure in measures:
        data = BodyMeasure.query.get(measure.grpid)

        if data:
            data.from_measure(measure)
        else:
            data = BodyMeasure()
            data.from_measure(measure)
            db.session.add(data)

    ws.value['lastupdate'] = datetime_to_epoch(datetime.now())

    db.session.commit()


def withings_get_measures(offset=0, days=30, to_json=False):
    """ Returns a dict(key=EPOCH_TS, value=list(BodyMeasure)) """

    t = date.today()
    d = relativedelta(days=days * offset)

    date0 = t - relativedelta(days=days - 1, hour=0, minute=0, second=0) - d
    date1 = t + relativedelta(days=0, hour=23, minute=59, second=59) - d

    measures = BodyMeasure.query.filter_by(
        category=WITHINGS_CATEGORY_MEASURE,
        attribution=WITHINGS_ATTRIBUTION_USER
    ).filter(
        BodyMeasure.date.between(date0, date1),
        BodyMeasure.weight.isnot(None)
    ).order_by(BodyMeasure.date.desc()).all()

    data = {}
    for dt in rrule.rrule(rrule.DAILY, dtstart=date0, until=date1):
        data[timegm(dt.timetuple()) * 1000] = []

    for measure in measures:
        dt = timegm(measure.date.date().timetuple()) * 1000
        data[dt].append(measure)

    if to_json:
        measure_handler = lambda obj: obj.get_dict() \
            if isinstance(obj, BodyMeasure) else None

        return json.dumps(data, use_decimal=True, default=measure_handler)

    return data
