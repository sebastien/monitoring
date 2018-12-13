#!/usr/bin/env python
# Encoding: utf-8
# See: <http://docs.python.org/distutils/introduction.html>
from distutils.core import setup
VERSION = eval(list(filter(lambda _:_.startswith("__version__"), open("src/monitoring/__init__.py").readlines()))[0].split("=")[1])
setup(
	name             = "monitoring",
	version          = VERSION,
	description      = "Server monitoring and data-collection daemon",
	author           = "Sébastien Pierre",
	author_email     = "sebastien.pierre@gmail.com",
	url              = "http://github.com/sebastien/monitoring",
	download_url     = "https://github.com/sebastien/monitoring/tarball/%s" % (VERSION),
	keywords         = ["daemon", "services", "monitoring", "administration"],
	install_requires = [],
	package_dir      = {"":"src"},
	packages         = ["monitoring", "monitoring.rules", "monitoring.actions"],
	scripts          = ["Scripts/monitoring"],
    license          = "License :: OSI Approved :: BSD License",
	classifiers      = [
		"Programming Language :: Python",
		"Development Status :: 3 - Alpha",
		"Natural Language :: English",
		"Environment :: Web Environment",
		"Intended Audience :: Developers",
		"Operating System :: OS Independent",
		"Topic :: Utilities"
	],
)
# EOF - vim: ts=4 sw=4 noet
