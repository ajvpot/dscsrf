import string
from random import SystemRandom

from flask import request, after_this_request
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
		self.app.jinja_env.globals['csrf_token'] = self.csrf_token

	def csrf_token(self):
		if hasattr(request, '_tmp_csrf'):
			token = request._tmp_csrf
		else:
			token = request.cookies.get(self.cookieName)
		return Markup('<input type="hidden" name="{0}" value="{1}" />'.format(self.paramName, token))

	def checkCSRFCookie(self):
		cookie = request.cookies.get(self.cookieName, None)
		if cookie is None:
			cookie = ''.join([_rng.choice(csrf_charset) for _ in xrange(64)])
			request._tmp_csrf = cookie  # hacks

			@after_this_request
			def setCookie(response):
				response.set_cookie(self.cookieName, cookie)
				return response
		if request.method != 'POST':
			return
		if cookie is None:
			return 'CSRF cookie not set.', 403
		form = request.form.get(self.paramName, None)
		if form is None:
			return 'CSRF form value not set.', 403
		if cookie != form:
			return 'CSRF token invalid.', 403
