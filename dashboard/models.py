# -*- coding: utf-8 -*-

from dashboard import db


class Setting(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(db.Text())

    def __repr__(self):
        return '<User %r>' % self.key
