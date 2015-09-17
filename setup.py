from distutils.core import setup
import os, sys

setup(name='dscsrf',
	version='1.0',
	url='https://github.com/sc4reful/dscsrf',
	license='MIT',
	author='sc4reful',
	author_email='notanemail@insorg-mail.info',
	description='Double-submit CSRF protection for Flask applications.',
	py_modules=['dscsrf'],
	zip_safe=False,
	platforms='any',
	install_requires=['Flask'],
	classifiers = [
		'Environment :: Web Environment',
		'Intended Audience :: Developers',
		'License :: OSI Approved :: MIT License',
		'Operating System :: OS Independent',
		'Programming Language :: Python',
		'Topic :: Software Development :: Libraries :: Python Modules'
	],
)
