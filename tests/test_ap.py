from unittest import TestCase
import tempfile
import os
import shutil

from wifi_ap import Hostapd, Dnsmasq

HOSTAPD_FILE_WITHOUT_ENCRYPTION = """interface=wlan0
driver=nl80211
ssid=SsidWithoutEncryption
channel=3
"""

HOSTAPD_FILE_WITH_ENCRYPTION = """interface=wlan0
driver=madwifi
ssid=SsidWithEncryption
channel=5
wpa=3
wpa_passphrase=MySecretPresharedKey
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
rsn_pairwise=CCMP
hw_mode=g
auth_algs=3
"""

class TestHostapd(TestCase):

    def setUp(self):
        self.confd = tempfile.mkdtemp()

        with open(os.path.join(self.confd, "ssid_without_encryption.conf"), "w") as f:
            f.write(HOSTAPD_FILE_WITHOUT_ENCRYPTION)

        with open(os.path.join(self.confd, "ssid_with_encryption.conf"), "w") as f:
            f.write(HOSTAPD_FILE_WITH_ENCRYPTION)

        self.Hostapd = Hostapd.for_hostapd_and_confd(None, self.confd)

    def tearDown(self):
        shutil.rmtree(self.confd)

    def test_str(self):
        hostapd = self.Hostapd('wlan0', 'some_name', 'SomeSsid', 3)
        self.assertEquals(str(hostapd), "interface=wlan0\ndriver=nl80211\nssid=SomeSsid\nchannel=3")

        hostapd = self.Hostapd('wlan0', 'some_name', 'SomeSsid', 3, driver='madwifi')
        self.assertEquals(str(hostapd), "interface=wlan0\ndriver=madwifi\nssid=SomeSsid\nchannel=3")

        hostapd = self.Hostapd('wlan0', 'some_name', 'SomeSsid', 3, psk="SuperSecret")
        self.assertEqual(str(hostapd), "interface=wlan0\ndriver=nl80211\nssid=SomeSsid\nchannel=3\nwpa=3\nwpa_passphrase=SuperSecret\nwpa_key_mgmt=WPA-PSK\nwpa_pairwise=TKIP CCMP\nrsn_pairwise=CCMP")

        hostapd = self.Hostapd('wlan0', 'some_name', 'SomeSsid', 3, options=dict(some_option="some_value"))
        self.assertEquals(str(hostapd), "interface=wlan0\ndriver=nl80211\nssid=SomeSsid\nchannel=3\nsome_option=some_value")

    def test_find(self):
        with_encryption = self.Hostapd.find('wlan0', 'ssid_with_encryption')
        self.assertIsNotNone(with_encryption)
        self.assertEquals(with_encryption.ssid, "SsidWithEncryption")

        wrong_interface = self.Hostapd.find('wlan1', 'ssid_with_encryption')
        self.assertIsNone(wrong_interface)

        unknown = self.Hostapd.find('wlan0', 'unknown_ssid')
        self.assertIsNone(unknown)

    def test_delete(self):
        with_encryption = self.Hostapd.find('wlan0', 'ssid_with_encryption')
        with_encryption.delete()
        self.assertIsNone(self.Hostapd.find('wlan0', 'ssid_with_encryption'))
        self.assertIsNotNone(self.Hostapd.find('wlan0', 'ssid_without_encryption'))

    def test_parse(self):
        hostapd = self.Hostapd.from_hostapd_conf(os.path.join(self.confd, "ssid_without_encryption.conf"))
        self.assertEquals("wlan0", hostapd.interface)
        self.assertEquals("ssid_without_encryption", hostapd.name)
        self.assertEquals("SsidWithoutEncryption", hostapd.ssid)
        self.assertEquals(3, hostapd.channel)
        self.assertEquals("nl80211", hostapd.driver)
        self.assertIsNone(hostapd.psk)
        self.assertDictEqual(dict(), hostapd.options)

        hostapd = self.Hostapd.from_hostapd_conf(os.path.join(self.confd, "ssid_with_encryption.conf"))
        self.assertEquals("wlan0", hostapd.interface)
        self.assertEquals("ssid_with_encryption", hostapd.name)
        self.assertEquals("SsidWithEncryption", hostapd.ssid)
        self.assertEquals(5, hostapd.channel)
        self.assertEquals("madwifi", hostapd.driver)
        self.assertEquals("MySecretPresharedKey", hostapd.psk)
        self.assertEquals(2, len(hostapd.options))
        self.assertTrue("hw_mode" in hostapd.options)
        self.assertEquals("g", hostapd.options["hw_mode"])
        self.assertTrue("auth_algs" in hostapd.options)
        self.assertEquals("3", hostapd.options["auth_algs"])


    def test_save(self):
        hostapd = self.Hostapd('wlan0', 'test', 'Test', 3)
        hostapd.save()
        self.assertIsNotNone(self.Hostapd.find('wlan0', 'test'))

    def test_save_overwrite(self):
        hostapd = self.Hostapd('wlan0', 'ssid_without_encryption', 'SsidWithoutEncryption', 3, driver='madwifi')

        try:
            hostapd.save()
            self.fail("Expected an exception")
        except:
            pass

        existing_hostapd = self.Hostapd.find('wlan0', 'ssid_without_encryption')
        self.assertIsNotNone(existing_hostapd)
        self.assertEquals(existing_hostapd.driver, 'nl80211')

        hostapd.save(allow_overwrite=True)
        existing_hostapd = self.Hostapd.find('wlan0', 'ssid_without_encryption')
        self.assertIsNotNone(existing_hostapd)
        self.assertEquals(existing_hostapd.driver, 'madwifi')


DNSMASQ_FILE_1 = """interface=wlan0
bind-interfaces
dhcp-range=192.168.0.100,192.168.0.200,600
"""

DNSMASQ_FILE_2 = """interface=wlan0
bind-interfaces
dhcp-range=10.10.0.1,10.10.254.254,7200
local=/mydomain/
domain=mydomain
expand-hosts
dhcp-option=option:router,10.0.0.1
dhcp-option=option:ntp-server,10.0.0.2
read-ethers
"""

DNSMASQ_FILE_3 = """interface=wlan0
bind-interfaces
dhcp-range=192.168.0.100,192.168.0.200,5m
"""

DNSMASQ_FILE_4 = """interface=wlan0
bind-interfaces
dhcp-range=192.168.0.100,192.168.0.200,12h
"""


class TestDnsmasq(TestCase):

    def setUp(self):
        self.confd = tempfile.mkdtemp()

        with open(os.path.join(self.confd, "dnsmasq_1.conf"), "w") as f:
            f.write(DNSMASQ_FILE_1)

        with open(os.path.join(self.confd, "dnsmasq_2.conf"), "w") as f:
            f.write(DNSMASQ_FILE_2)

        with open(os.path.join(self.confd, "dnsmasq_3.conf"), "w") as f:
            f.write(DNSMASQ_FILE_3)

        with open(os.path.join(self.confd, "dnsmasq_4.conf"), "w") as f:
            f.write(DNSMASQ_FILE_4)

        self.Dnsmasq = Dnsmasq.for_dnsmasq_and_confd(None, self.confd)

    def tearDown(self):
        shutil.rmtree(self.confd)

    def test_str(self):
        dnsmasq = self.Dnsmasq("wlan0", "test", "192.168.1.100", "192.168.1.200")
        self.assertEquals(str(dnsmasq), "interface=wlan0\nbind-interfaces\ndhcp-range=192.168.1.100,192.168.1.200,600")

        dnsmasq = self.Dnsmasq("wlan0", "test", "10.10.0.1", "10.10.254.254", lease_time=7200, gateway="10.0.0.1", domain="mydomain")
        self.assertEquals(str(dnsmasq), "interface=wlan0\nbind-interfaces\ndhcp-range=10.10.0.1,10.10.254.254,7200\nlocal=/mydomain/\ndomain=mydomain\nexpand-hosts\ndhcp-option=option:router,10.0.0.1")

        dnsmasq = self.Dnsmasq("wlan0", "test", "10.10.0.1", "10.10.254.254", gateway="10.0.0.1", options={"dhcp-option": ["option:ntp-server,10.0.0.2"]})
        self.assertEquals(str(dnsmasq), "interface=wlan0\nbind-interfaces\ndhcp-range=10.10.0.1,10.10.254.254,600\ndhcp-option=option:router,10.0.0.1\ndhcp-option=option:ntp-server,10.0.0.2")

    def test_parse(self):
        dnsmasq = self.Dnsmasq.from_dnsmasq_conf(os.path.join(self.confd, "dnsmasq_1.conf"))
        self.assertEquals("wlan0", dnsmasq.interface)
        self.assertEquals("dnsmasq_1", dnsmasq.name)
        self.assertEquals("192.168.0.100", dnsmasq.start)
        self.assertEquals("192.168.0.200", dnsmasq.end)
        self.assertEquals(600, dnsmasq.lease_time)
        self.assertIsNone(dnsmasq.gateway)
        self.assertIsNone(dnsmasq.domain)
        self.assertDictEqual(dict(), dnsmasq.options)

        dnsmasq = self.Dnsmasq.from_dnsmasq_conf(os.path.join(self.confd, "dnsmasq_2.conf"))
        self.assertEquals("wlan0", dnsmasq.interface)
        self.assertEquals("dnsmasq_2", dnsmasq.name)
        self.assertEquals("10.10.0.1", dnsmasq.start)
        self.assertEquals("10.10.254.254", dnsmasq.end)
        self.assertEquals(7200, dnsmasq.lease_time)
        self.assertEquals("10.0.0.1", dnsmasq.gateway)
        self.assertEquals("mydomain", dnsmasq.domain)
        self.assertEquals(2, len(dnsmasq.options))
        self.assertTrue("dhcp-option" in dnsmasq.options)
        self.assertEquals(1, len(dnsmasq.options["dhcp-option"]))
        self.assertEquals("option:ntp-server,10.0.0.2", dnsmasq.options["dhcp-option"][0])
        self.assertTrue("read-ethers" in dnsmasq.options)
        self.assertIsNone(dnsmasq.options["read-ethers"])

        dnsmasq = self.Dnsmasq.from_dnsmasq_conf(os.path.join(self.confd, "dnsmasq_3.conf"))
        self.assertEquals(300, dnsmasq.lease_time)

        dnsmasq = self.Dnsmasq.from_dnsmasq_conf(os.path.join(self.confd, "dnsmasq_4.conf"))
        self.assertEquals(43200, dnsmasq.lease_time)

    def test_find(self):
        self.assertIsNotNone(self.Dnsmasq.find("wlan0", "dnsmasq_1"))
        self.assertIsNone(self.Dnsmasq.find("eth0", "dnsmasq_1"))
        self.assertIsNone(self.Dnsmasq.find("wlan0", "unknown"))

    def test_save(self):
        dnsmasq = self.Dnsmasq('wlan0', 'test', '192.168.10.10', '192.168.10.20')
        dnsmasq.save()
        self.assertIsNotNone(self.Dnsmasq.find('wlan0', 'test'))
        pass

    def test_save_overwrite(self):
        dnsmasq = self.Dnsmasq('wlan0', 'dnsmasq_1', '192.168.10.100', '192.168.10.200')

        try:
            dnsmasq.save()
            self.fail("Expected an exception")
        except:
            pass

        existing_dnsmasq = self.Dnsmasq.find('wlan0', 'dnsmasq_1')
        self.assertIsNotNone(existing_dnsmasq)
        self.assertEquals(existing_dnsmasq.start, '192.168.0.100')
        self.assertEquals(existing_dnsmasq.end, '192.168.0.200')

        dnsmasq.save(allow_overwrite=True)
        existing_dnsmasq = self.Dnsmasq.find('wlan0', 'dnsmasq_1')
        self.assertIsNotNone(existing_dnsmasq)
        self.assertEquals(existing_dnsmasq.start, '192.168.10.100')
        self.assertEquals(existing_dnsmasq.end, '192.168.10.200')
