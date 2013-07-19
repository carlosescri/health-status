# -*- coding: utf-8 -*-

from random import choice

from flask.ext.classy import FlaskView, route

from dashboard import app

quotes = [
    "A noble spirit embiggens the smallest man! ~ Jebediah Springfield",
    "If there is a way to do it better... find it. ~ Thomas Edison",
    "No one knows what he can do till he tries. ~ Publilius Syrus"
]


# http://pythonhosted.org/Flask-Classy/
class QuotesView(FlaskView):
    route_base = '/'

    def index(self):
        return "<br>".join(quotes)

    def get(self, id):
        id = int(id)
        if id <= len(quotes):
            return quotes[id - 1]
        else:
            return "Not Found", 404

    @route('/word_bacon/')
    def random(self):
        return choice(quotes)

QuotesView.register(app)
