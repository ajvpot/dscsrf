import string
from flask import request
from random import SystemRandom
from markupsafe import Markup

csrf_charset = string.letters + string.digits

_rng = SystemRandom()

class Csrf(object):
	def __init__(self, app=None, paramName='dscsrf', cookieName='dscsrf'):
		self.app = None
		self.paramName = paramName
		self.cookieName = cookieName

		if app is not None:
			self.init_app(app, paramName, cookieName)

	def init_app(self, app, paramName='dscsrf', cookieName='dscsrf'):
		self.app = app
		self.paramName = paramName
		self.cookieName = cookieName

		self.app.before_request(self.checkCSRFCookie)
		self.app.after_request(self.setCSRFCookie)
		self.app.jinja_env.globals['csrf_token'] = self.csrf_token

	def csrf_token(self):
		return Markup('<input type="hidden" name="{0}" value="{1}" />'.format(self.paramName, request.cookies.get(self.cookieName)))


	def checkCSRFCookie(self):
		if request.method != 'POST':
			return
		cookie = request.cookies.get(self.cookieName, None)
		if cookie is None:
			return 'CSRF cookie not set.', 403
		form = request.form.get(self.paramName, None)
		if form is None:
			return 'CSRF form value not set.', 403
		if cookie != form:
			return 'CSRF token invalid.', 403

	def setCSRFCookie(self, response):
		rc = request.cookies.get(self.cookieName, None)
		if rc is None:
			cookie = ''.join([_rng.choice(csrf_charset) for _ in xrange(64)])
			response.set_cookie(self.cookieName, cookie)
		return response
