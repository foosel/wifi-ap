# coding=utf-8
#!/usr/bin/env python

from setuptools import setup

__doc__ = """
Library wrappers around hostapd and dnsmasq for programmatically creating access points
"""

def params():
	name = "wifi-ap"
	version = "0.1.0"

	author = "Gina Häußge"
	author_email = "osd@foosel.net"

	description = __doc__
	long_description = open("README.md").read()

	platforms = ["Debian"]
	license = "BSD"
	classifiers = [
		"License :: OSI Approved :: BSD License",
		"Topic :: System :: Networking",
		"Operating System :: POSIX :: Linux",
		"Environment :: Console",
		"Programming Language :: Python",
		"Programming Language :: Python :: 2.6",
		"Programming Language :: Python :: 2.7",
		"Programming Language :: Python :: 3.3",
	]

	packages = ["wifi_ap"]
	dependency_links = [
		"https://github.com/foosel/wifi/tarball/master#egg=wifi-1.0.1"
	]
	install_requires = [
		"setuptools",
		"netaddr",
		"wifi==1.0.1"
	]

	test_suite = "tests"

	return locals()

setup(**params())
