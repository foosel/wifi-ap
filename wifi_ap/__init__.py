from __future__ import print_function, absolute_import

import netaddr
import os
import logging
import re

from wifi import Scheme
import wifi.subprocess_compat as subprocess

from wifi_ap.exceptions import ApError, ApBindError, ApInterfaceError, ApSchemeError



cidr_v4_pattern = r"(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(\d|[1-2]\d|3[0-2]))"
mac_addr_pattern = r"[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}"

bound_ap_re = re.compile(r"^Using interface (?P<interface>\w+) with hwaddr %s and ssid '(?P<ssid>[^']+)'" % mac_addr_pattern, flags=re.MULTILINE)


class Hostapd(object):
	"""
	A wrapper for managing hostapd configuration files stored under /etc/hostapd/conf.d and
	managing hostapd service instances based on them.

	Note: The directory /etc/hostapd/conf.d does not usually exist and has to be created before using
	this class. Alternatively provide a different location for file storage by creating a custom type
	wrapper using `Hostapd.for_hostapd_and_confd(hostapd=<hostapd>, confd=<config folder>)`.
	"""

	# location of hostapd binary
	hostapd = "/usr/sbin/hostapd"

	# location of hostapd config folder
	confd = "/etc/hostapd/conf.d/"

	# our logger instance
	logger = logging.getLogger(__name__)

	@classmethod
	def for_hostapd_and_confd(cls, hostapd, confd):
		return type(cls)(cls.__name__, (cls,), {
			'hostapd': hostapd if hostapd is not None else cls.hostapd,
			'confd': confd if confd is not None else cls.confd,
			})

	def __init__(self, interface, name, ssid, channel, driver=None, psk=None, options=None):
		self.interface = interface
		self.driver = driver if driver is not None else "nl80211"
		self.name = name
		self.ssid = ssid
		self.channel = channel
		self.psk = psk

		self.options = options if options else dict()

	def __str__(self):
		# default parameters for a simply ap
		conf = [
			"interface={interface}",
			"driver={driver}",
			"ssid={ssid}",
			"channel={channel}"
		]

		if self.psk is not None:
			# parameters for encryption via WPA
			conf += [
				"wpa=3",
				"wpa_passphrase={psk}",
				"wpa_key_mgmt=WPA-PSK",
				"wpa_pairwise=TKIP CCMP",
				"rsn_pairwise=CCMP"
			]

		if self.options:
			# any additional options given
			conf += ["{k}={v}".format(k=k, v=v) for k, v in self.options.items()]

		return "\n".join(conf).format(**vars(self))

	def __repr__(self):
		return "Hostapd(interface={interface!r}, driver={driver!r}, name={name!r}, ssid={ssid!r})" \
			.format(**vars(self))

	def save(self, allow_overwrite=False):
		existing_hostapd = self.__class__.find(self.interface, self.name)
		if existing_hostapd:
			if not allow_overwrite:
				raise RuntimeError("Config for interface %s named %s does already exists and overwrite is not allowed" % (self.interface, self.name))
			existing_hostapd.delete()

		with open(self.configfile, "w") as f:
			f.write(str(self))

	def delete(self):
		if self.is_running():
			self.deactivate()

		try:
			os.remove(self.configfile)
		except OSError as e:
			self._logger.warn("Could not delete %s: %s" % (self.configfile, e))

	def activate(self):
		try:
			output = subprocess.check_output([self.__class__.hostapd, "-dd", "-B", self.configfile], stderr=subprocess.STDOUT)
			self._logger.info("Started hostapd: {output}".format(output=output))
			return True
		except subprocess.CalledProcessError as e:
			self._logger.warn("Error while starting hostapd: {output}".format(output=e.output))
			raise e

	def deactivate(self):
		pid = self.get_pid()
		if pid is None:
			return
		try:
			subprocess.check_output(["kill", pid])
		except subprocess.CalledProcessError as e:
			self._logger.warn("Error while stopping hostapd: {output}".format(output=e.output))
			raise e

	def get_pid(self):
		pids = [pid for pid in os.listdir("/proc") if pid.isdigit()]
		for pid in pids:
			try:
				with open(os.path.join("/proc", pid, "cmdline"), "r") as f:
					line = f.readline()
					if self.__class__.hostapd in line and self.configfile in line:
						return pid
			except:
				# the pid might just have vanished because the process exited normally, no need to worry
				pass
		return None

	def is_running(self):
		return self.get_pid() is not None

	@property
	def configfile(self):
		return os.path.join(self.__class__.confd, "{name}.conf".format(name=self.name))

	@property
	def _logger(self):
		return self.__class__.logger

	@classmethod
	def all(cls):
		result = []
		for conf in os.listdir(cls.confd):
			if conf.endswith(".conf"):
				filename = os.path.join(cls.confd, conf)
				try:
					ap = cls.from_hostapd_conf(filename)
					result.append(ap)
				except:
					cls.logger.exception("Could not retrieve hostapd from file %s:" % filename)
		return result

	@classmethod
	def find(cls, interface, name):
		try:
			return cls.where(lambda x: x.name == name and x.interface == interface)[0]
		except IndexError:
			return None

	@classmethod
	def where(cls, fn):
		return list(filter(fn, cls.all()))

	@classmethod
	def from_hostapd_conf(cls, configfile):
		if not os.path.exists(configfile):
			raise IOError("Configfile not found: %s" % configfile)

		name = os.path.basename(configfile)[:-len(".conf")]

		conf_options = dict()
		with open(configfile, "r") as f:
			for line in f:
				k, v = line.strip().split("=", 1)
				conf_options[k] = v

		for key in ("interface", "ssid", "channel"):
			if not key in conf_options or conf_options[key] is None:
				raise RuntimeError("Invalid config, %s is missing or none" % key)

		options = dict((k, conf_options[k]) for k in conf_options if not k in ["interface", "driver", "ssid", "channel", "wpa", "wpa_passphrase", "wpa_key_mgmt", "wpa_pairwise", "rsn_pairwise"])
		psk = conf_options["wpa_passphrase"] if "wpa_passphrase" in conf_options else None
		try:
			channel = int(conf_options["channel"])
		except ValueError as e:
			raise RuntimeError("Invalid config, %r is an invalid channel" % conf_options["channel"], e)

		return cls(conf_options["interface"], name, conf_options["ssid"], channel, driver=conf_options["driver"], psk=psk, options=options)


	def parse_hostapd_output(self, output):
		print(output)
		matches = bound_ap_re.search(output)
		if matches:
			return True
		else:
			raise ApBindError("Could not bind hostapd %r to interface %s:\n%s" % (self, self.interface, output))


class Dnsmasq(object):
	"""
	A wrapper for managing dnsmasq configurations (stored as .conf files under /etc/dnsmasq.conf.d)
	and managing dnsmasq service instances based on them.

	Note: The directory /etc/dnsmasq.conf.d does not usually exist and has to be created before using
	this class. Alternatively provide a different location for file storage by creating a custom type
	wrapper using `Dnsmasq.for_dnsmasq_and_confd(dnsmasq=<dnsmasq>, confd=<config folder>)`.
	"""

	# dnsmasq binary
	dnsmasq = "/usr/sbin/dnsmasq"

	# dnsmasq configuration storage
	confd = "/etc/dnsmasq.conf.d"

	# our logger
	logger = logging.getLogger(__name__)

	@classmethod
	def for_dnsmasq_and_confd(cls, dnsmasq, confd):
		return type(cls)(cls.__name__, (cls,), {
			'dnsmasq': dnsmasq if dnsmasq is not None else cls.dnsmasq,
			'confd': confd if confd is not None else cls.confd,
			})

	@classmethod
	def all(cls):
		result = []
		for conf in os.listdir(cls.confd):
			if conf.endswith(".conf"):
				filename = os.path.join(cls.confd, conf)
				try:
					dnsmasq = cls.from_dnsmasq_conf(os.path.join(cls.confd, conf))
					result.append(dnsmasq)
				except:
					cls.logger.exception("Could not retrieve dnsmasq config from file %s" % filename)
		return result

	@classmethod
	def where(cls, fn):
		return list(filter(fn, cls.all()))

	@classmethod
	def find(cls, interface, name):
		try:
			return cls.where(lambda x: x.name == name and x.interface == interface)[0]
		except IndexError:
			return None

	@classmethod
	def from_dnsmasq_conf(cls, configfile):
		"""
		Creates a :class:`Dnsmasq` config from a given dnsmasq configuration file.

		:param configfile: path of config file to create instance from
		:return: created instance
		"""

		if not os.path.exists(configfile):
			raise IOError("Configfile not found: %s" % configfile)

		name = os.path.basename(configfile)[:-len(".conf")]

		conf = dict()
		additional_options = dict()
		with open(configfile, "r") as f:
			for line in f:
				line = line.strip()
				if not line:
					continue

				# split or "key=value" pairs
				split_line = map(str.strip, line.split("=", 1))
				if len(split_line) > 1:
					# this is an actual "key=value" pair
					k, v = split_line
				else:
					# this is only a single "key" option without value
					k = split_line[0]
					v = None

				if k == "interface":
					conf["interface"] = v
					continue

				elif k == "dhcp-range":
					# format is either "dhcp-range=<ip1>,<ip2>,<leasetime>" or
					# "dhcp-range=<tag>,<ip1>,<ip2>,<leasetime>"
					opts = v.split(",")
					if len(opts) > 3:
						# strip off tags, we don't care about them
						opts = opts[-3:]
					conf["start"], conf["end"], lease_time = opts

					# lease time can be given as "<hours>h", "<minutes>m" or "<seconds>"
					if lease_time.endswith("h"):
						# hours = 60 minutes * 60 seconds
						factor = 60 * 60
						lease_time = lease_time[:-1]
					elif lease_time.endswith("m"):
						# minutes = 60 seconds
						factor = 60
						lease_time = lease_time[:-1]
					else:
						# seconds
						factor = 1

					try:
						conf["lease_time"] = int(lease_time) * factor
						continue
					except ValueError:
						cls.logger.exception("Could not convert lease time value %s" % lease_time)

				elif k == "domain":
					conf["domain"] = v
					continue

				elif k == "dhcp-option":
					# parse dhcp options, right now we only support gateway definition, which
					# is provided in the format "dhcp-option=option:router,<gateway>" or
					# "dhcp-option=3,<gateway>"
					opts = v.split(",")
					if len(opts) == 2 and (opts[0] == "option:router" or opts[0] == "3"):
						conf["gateway"] = opts[1]
						continue

				elif k in ("bind-interfaces", "local", "expand-hosts"):
					# ignore known parameters that are used for general setup or domain setup
					continue

				# if we came this far then we have an additional option at hand
				if v is not None:
					# if the value is not None, we create a key => list entry and add the value to it
					if not k in additional_options:
						additional_options[k] = list()
					additional_options[k].append(v)
				else:
					# if the value is None it's a key only entry, so we add a key => None entry
					additional_options[k] = None

		# make sure the mandatory parameters are all there
		for key in "interface", "start", "end":
			if not key in conf or conf[key] is None:
				raise RuntimeError("Invalid config, %s is missing or None" % key)

		# make sure the optional arguments that are not supplied are all set to None
		for key in "lease_time", "domain", "gateway":
			if not key in conf:
				conf[key] = None

		return Dnsmasq(conf["interface"], name, conf["start"], conf["end"], lease_time=conf["lease_time"],
		               gateway=conf["gateway"], domain=conf["domain"], options=additional_options)


	def __init__(self, interface, name, start, end, lease_time=None, gateway=None, domain=None, options=None):
		"""
		:param interface: the interface on which to listen
		:param name: the name of the configuration
		:param start: the start ip of the managed dhcp range
		:param end: the end ip of the managed dhcp range
		:param lease_time: the lease time for given dhcp leases, defaults to 600s
		:param gateway: the gateway to hand out via dhcp, defaults to no gateway
		:param domain: the local domain to define, default to no domain
		:param options: additional options, dict of either key => list (for possibly
			   multiple key-value-pairs) or key => None for key-only-statements
			   in the config
		"""

		self.interface = interface
		self.name = name
		self.start = start
		self.end = end
		self.lease_time = lease_time if lease_time else 600
		self.gateway = gateway
		self.domain = domain
		self.options = options if options else dict()

	def __str__(self):
		# basic dhcp setup for dnsmasq
		conf = [
			"interface={interface}",
			"bind-interfaces",
			"dhcp-range={start},{end},{lease_time}"
		]

		# if a local domain is configured, add the corresponding configuration lines
		if self.domain:
			conf += [
				"local=/{domain}/",
				"domain={domain}",
				"expand-hosts"
			]

		# if a gateway is configured, add the corresponding configuration line
		if self.gateway:
			conf += [
				"dhcp-option=option:router,{gateway}"
			]

		# add any additional dnsmasq options that were provided
		if self.options:
			for k, l in self.options.items():
				if l is not None:
					for v in l:
						conf.append("{key}={value}".format(key=k, value=v))
				else:
					conf.append(k)

		return "\n".join(conf).format(**vars(self))

	def __repr__(self):
		return "Dnsmasq(interface={interface}, name={name}, start={start}, end={end})".format(**vars(self))

	def save(self, allow_overwrite=False):
		"""
		Saves the config to the defined `confd` directory.

		:param allow_overwrite: whether to overwrite an existing config of the same name, raises an
								exception if such a config is found and set to `False` (the default)
		"""

		existing_dnsmasq = self.__class__.find(self.interface, self.name)
		if existing_dnsmasq:
			if not allow_overwrite:
				raise RuntimeError("Config for interface %s named %s does already exists and overwrite is not allowed" % (self.interface, self.name))
			existing_dnsmasq.delete()

		with open(self.configfile, "w") as f:
			f.write(str(self))

	def delete(self):
		""" Deletes the config, deactivates it before if it's currently active. """

		if self.is_running():
			self.deactivate()
		try:
			os.remove(self.configfile)
		except OSError as e:
			self._logger.warn("Could not delete %s: %s" % (self.configfile, e))

	def activate(self):
		""" Activates this config. """

		try:
			output = subprocess.check_output([self.__class__.dnsmasq, "--conf-file={file}".format(file=self.configfile)], stderr=subprocess.STDOUT)
			self._logger.info("Started dnsmasq: {output}".format(output=output))
		except subprocess.CalledProcessError as e:
			self._logger.warn("Error while starting dnsmasq: {output}".format(output=e.output))
			raise e

	def deactivate(self):
		""" Deactivates this config. """

		pid = self.get_pid()
		if pid is None:
			return
		try:
			subprocess.check_output(["kill", pid])
		except subprocess.CalledProcessError as e:
			self._logger.warn("Error while stopping dnsmasq: {output}".format(output=e.output))
			raise e

	def get_pid(self):
		""" Get's the pid of the dnsmasq process running this config, or None if not currently running. """

		pids = [pid for pid in os.listdir("/proc") if pid.isdigit()]
		for pid in pids:
			try:
				with open(os.path.join("/proc", pid, "cmdline"), "r") as f:
					line = f.readline()
					if self.__class__.dnsmasq in line and self.configfile in line:
						return pid
			except:
				pass
		return None

	def is_running(self):
		""" Returns a boolean indicating whether this config is currently active or not. """

		return self.get_pid() is not None

	@property
	def configfile(self):
		return os.path.join(self.__class__.confd, "{name}.conf".format(name=self.name))

	@property
	def _logger(self):
		return self.__class__.logger


class AccessPoint(object):
	"""
	Manages access point configurations by wrapping the hostapd, dnsmasq and scheme configurations
	they are based on and allows starting and stopping the access point altogether.
	"""

	# class providing the hostapd wrapper
	hostapd_cls = Hostapd

	# class providing the dnsmasq wrapper
	dnsmasq_cls = Dnsmasq

	# class providing the scheme wrapper
	scheme_cls = Scheme

	@classmethod
	def for_classes(cls, hostapd_cls=None, dnsmasq_cls=None, scheme_cls=None):
		return type(cls)(cls.__name__, (cls,), {
			'hostapd_cls': hostapd_cls if hostapd_cls is not None else cls.hostapd_cls,
			'dnsmasq_cls': dnsmasq_cls if dnsmasq_cls is not None else cls.dnsmasq_cls,
			'scheme_cls': scheme_cls if scheme_cls is not None else cls.scheme_cls
		})

	@classmethod
	def all(cls):
		hostapds = {(hostapd.interface, hostapd.name): hostapd for hostapd in cls.hostapd_cls.all()}
		dnsmasqs = {(dnsmasq.interface, dnsmasq.name): dnsmasq for dnsmasq in cls.dnsmasq_cls.all()}
		schemes = {(scheme.interface, scheme.name): scheme for scheme in cls.scheme_cls.all()}

		result = []
		for key in hostapds:
			if key in dnsmasqs and key in schemes:
				result.append(AccessPoint(hostapds[key], dnsmasqs[key], schemes[key]))
		return result

	@classmethod
	def where(cls, fn):
		return list(filter(fn, cls.all()))

	@classmethod
	def find(cls, interface, name):
		try:
			return cls.where(lambda x: x.name == name and x.interface == interface)[0]
		except IndexError:
			return None

	@classmethod
	def for_arguments(cls, interface, name, ssid, channel, ip, network, start, end, forwarding_to=None,
	                  hostap_options=None, dnsmasq_options=None, scheme_options=None):
		"""
		Creates a new access point configuration for the given arguments.

		:param string interface: the interface on which to create the access point
		:param string name: the configuration name
		:param string ssid: the SSID to create
		:param int channel: the channel on which to create the access point
		:param string ip: the ip to assign to the interface serving as access point
		:param string network: the network of the access point
		:param string start: start address of IP address range handled by dhcp server
		:param string end: end address of IP address range handled by dhcp server
		:param string forwarding_to: interface to forward to, defaults to None for no
			   forwarding enabled
		:param dict hostap_options: hostap options, defaults to None. Parameters
			   `driver` and `psk` will be used as their counterparts during
			   `Hostapd` construction, all other options will be given as
			   `options` to the Hostapd constructor.
		:param dict dnsmasq_options: dnsmasq options, defaults to None. Parameters
			   `lease_time`, `domain` and `gateway` will be used as their
			   counterparts during `Dnsmasq` construction, all other options
			   will be given as `options` to the Dnsmasq constructor.
		:param dict scheme_options: scheme options, defaults to None. Note that
			   `address`, `netmask` and `broadcast` will be overwritten with
			   the values derived from `ip` and `network`. If `forwarding_to`
			   is set `post-up` and `pre-down` will be extended to include
			   the necessary firewalling rules and forward-sysctl-calls
		:return: the resulting `AccessPoint` instance
		"""

		network_address = netaddr.IPNetwork(network)

		# prepare hostapd options
		if hostap_options is None:
			hostap_options = dict()

		if "driver" in hostap_options:
			driver = hostap_options["driver"]
			del hostap_options["driver"]
		else:
			driver = None

		if "psk" in hostap_options:
			psk = hostap_options["psk"]
			del hostap_options["psk"]
		else:
			psk = None

		# create hostapd config
		hostapd = cls.hostapd_cls(interface, name, ssid, channel, driver, psk=psk, options=hostap_options)

		#  prepare dnsmasq options
		if dnsmasq_options is None:
			dnsmasq_options = dict()

		if "lease_time" in dnsmasq_options:
			lease_time = dnsmasq_options["lease_time"]
			del dnsmasq_options["lease_time"]
		else:
			lease_time = None

		if "domain" in dnsmasq_options:
			domain = dnsmasq_options["domain"]
			del dnsmasq_options["domain"]
		else:
			domain = None

		if "gateway" in dnsmasq_options:
			gateway = dnsmasq_options["gateway"]
			del dnsmasq_options["gateway"]
		else:
			gateway = None

		# create dnsmasq
		dnsmasq = cls.dnsmasq_cls(interface, name, start, end, lease_time=lease_time, gateway=gateway, domain=domain, options=dnsmasq_options)

		# prepare scheme options
		if scheme_options == None:
			scheme_options = dict()

		# create a scheme with static configuration, given ip and netmask -- those parameters will be ruthlessly
		# overridden if they were already present in the supplied scheme_options
		scheme_options.update(dict(
			address=[ip],
			netmask=[str(network_address.netmask)],
			broadcast=[str(network_address.broadcast)]
		))

		if forwarding_to is not None:
			# if forwarding is enabled, also add some rules and stuff
			if not "post-up" in scheme_options:
				scheme_options["post-up"] = []
			scheme_options["post-up"] += [
				# flush current tables
				"/sbin/iptables -F",
				"/sbin/iptables -X",
				"/sbin/iptables -t nat -F",
				# setup forwarding rules
				"/sbin/iptables -A FORWARD -o {forward} -i {interface} -s {network} -m conntrack --ctstate NEW -j ACCEPT".format(forward=forwarding_to, network=str(network_address), interface=interface),
				"/sbin/iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
				"/sbin/iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
				# enable forwarding
				"/sbin/sysctl -w net.ipv4.ip_forward=1"
			]

			if not "pre-down" in scheme_options:
				scheme_options["pre-down"] = []
			scheme_options["pre-down"] += [
				# disable forwarding
				"/sbin/sysctl -w net.ipv4.ip_forward=0",
				# flush current tables
				"/sbin/iptables -F",
				"/sbin/iptables -X",
				"/sbin/iptables -t nat -F",
				]
		scheme = cls.scheme_cls(interface, name, type="static", options=scheme_options)

		return cls(hostapd, dnsmasq, scheme)

	def __init__(self, hostapd, dnsmasq, scheme):
		"""
		Constructor for the :class:`AccessPoint` instance, takes :class:`Hostapd`, :class:`Dnsmasq` and :class:`Scheme`
		instance to utilize.

		Should normally not be used directly from calling code, instead use the provided factory `for_arguments`.

		:param hostapd: :class:`Hostapd` instance
		:param dnsmasq: :class:`Dnsmasq` instance
		:param scheme: :class:`Scheme` instance
		"""

		self._logger = logging.getLogger(__name__)

		self.hostapd = hostapd
		self.dnsmasq = dnsmasq
		self.scheme = scheme

	def save(self, allow_overwrite=False):
		"""
		Saves all wrapped configurations.
		:param allow_overwrite: whether to allow overwriting of existing configs, defaults to False
		"""

		self.hostapd.save(allow_overwrite=allow_overwrite)
		self.dnsmasq.save(allow_overwrite=allow_overwrite)
		self.scheme.save(allow_overwrite=allow_overwrite)

	def delete(self):
		""" Deletes all wrapped configurations. """

		self.hostapd.delete()
		self.dnsmasq.delete()
		self.scheme.delete()

	def activate(self):
		""" Activates the access point by activating all wrapped configurations. """

		try:
			self.hostapd.activate()
			try:
				self.scheme.activate()
				self._logger.info("Started scheme")
			except subprocess.CalledProcessError as e:
				self._logger.warn("Error while activating scheme: {output}".format(output=e.output))
				raise ApSchemeError("Error while activating scheme".format(output=e.output), e)
			self.dnsmasq.activate()
		except subprocess.CalledProcessError as e:
			self._logger.warn("Error while activating access point")
			raise ApInterfaceError("Error while activating access point", e)

	def deactivate(self):
		""" Deactivates the access point by deactivating all wrapped configurations. """

		try:
			self.dnsmasq.deactivate()
			try:
				self.scheme.deactivate()
				self._logger.info("Stopped scheme")
			except subprocess.CalledProcessError as e:
				self._logger.warn("Error while deactivating scheme: {output}".format(output=e.output))
				raise ApSchemeError("Error while deactivating scheme", e)
			self.hostapd.deactivate()
		except subprocess.CalledProcessError as e:
			self._logger.warn("Error while deactivating access point")
			raise ApInterfaceError("Error while deactivating access point", e)

	@property
	def name(self):
		return self.hostapd.name

	@property
	def interface(self):
		return self.hostapd.interface

	def is_running(self):
		""" Returns whether the access point is currently running (either hostap or dnsmasq) or not. """
		return self.hostapd.is_running() or self.dnsmasq.is_running()

	def __repr__(self):
		return "AccessPoint(hostapd={hostapd!r}, dnsmasq={dnsmasq!r}, scheme={scheme!r})".format(**vars(self))

