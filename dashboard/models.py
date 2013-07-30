# -*- coding: utf-8 -*-

import json

from dashboard import db


class Setting(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text())

    def __repr__(self):
        return '<User %r>' % self.key

    def as_object(self):
        try:
            return json.loads(self.value)
        except ValueError:
            return {'value': self.value}

    def from_object(self, value):
        self.value = json.dumps(value)
