# -*- coding: utf-8 -*-

from withings import WithingsMeasureGroup

from dashboard import db
from dashboard.types import JSONAlchemy
from dashboard.const import WITHINGS_CATEGORY_MEASURE, WITHINGS_ATTRIBUTION_USER


class Setting(db.Model):
    key = db.Column(db.String(50), primary_key=True)
    value = db.Column(JSONAlchemy(db.Text()))

    def __repr__(self):
        return '<User %r>' % self.key

    @classmethod
    def get_or_create(cls, key, value=None):
        obj = cls.query.get(key)

        if obj is None:
            obj = Setting(key=key, value=value)
            db.session.add(obj)
            db.session.commit()

        return obj


class BodyMeasure(db.Model):
    __table_args__ = (
        db.Index('idx_body_measure_date', 'date'),
        db.Index('idx_body_measure_category_attribution', 'category',
                 'attribution'),
    )

    grpid = db.Column(db.BigInteger, primary_key=True, autoincrement=False)
    date = db.Column(db.DateTime, nullable=False)

    category = db.Column(db.SmallInteger, nullable=False,
                         default=WITHINGS_CATEGORY_MEASURE)
    attribution = db.Column(db.SmallInteger, nullable=False,
                            default=WITHINGS_ATTRIBUTION_USER)

    height = db.Column(db.Numeric(precision=5, scale=2))  # m.

    weight = db.Column(db.Numeric(precision=5, scale=2))  # kg.
    fat_free_mass = db.Column(db.Numeric(precision=5, scale=2))  # kg.
    fat_mass_weight = db.Column(db.Numeric(precision=5, scale=2))  # kg.
    fat_ratio = db.Column(db.Numeric(precision=5, scale=2))  # kg.

    heart_pulse = db.Column(db.Numeric(precision=5, scale=2))  # bpm
    systolic_blood_pressure = db.Column(db.Numeric(precision=5, scale=2))  # mmHg
    diastolic_blood_pressure = db.Column(db.Numeric(precision=5, scale=2))  # mmHg

    def from_measure(self, measure):
        assert isinstance(measure, WithingsMeasureGroup)

        if self.grpid:
            assert self.grpid == measure.grpid
        else:
            self.grpid = measure.grpid

        self.date = measure.date

        self.category = measure.category
        self.attribution = measure.attrib

        self.height = measure.height

        self.weight = measure.weight
        self.fat_free_mass = measure.fat_free_mass
        self.fat_mass_weight = measure.fat_mass_weight
        self.fat_ratio = measure.fat_ratio

        self.heart_pulse = measure.heart_pulse
        self.systolic_blood_pressure = measure.systolic_blood_pressure
        self.diastolic_blood_pressure = measure.diastolic_blood_pressure

    def get_dict(self):
        return {
            'grpid': self.grpid,
            'date': self.date.strftime('%Y-%m-%d'),
            'weight': self.weight,
            'fat_free_mass': self.fat_free_mass,
            'fat_mass_weight': self.fat_mass_weight,
            'fat_ratio': self.fat_ratio,
            'heart_pulse': self.heart_pulse,
            'systolic_blood_pressure': self.systolic_blood_pressure,
            'diastolic_blood_pressure': self.diastolic_blood_pressure,
        }
