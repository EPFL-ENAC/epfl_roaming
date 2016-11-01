tmpfile := $(shell mktemp /tmp/epfl_roaming.XXXXXX)

.PHONY: install
install:
	test -d /usr/local || mkdir -p /usr/local
	test -d /usr/local/bin || mkdir /usr/local/bin
	test -d /usr/local/etc || mkdir /usr/local/etc
	test -d /usr/local/lib || mkdir /usr/local/lib
	test -d /usr/local/lib/manage_cred || mkdir -m 700 /usr/local/lib/manage_cred
	test -d /etc/skel/.config/autostart || mkdir -p /etc/skel/.config/autostart
	test -d /etc/systemd/system || mkdir -p /etc/systemd/system
	apt-get -y install python-ldap
	grep -v 'manage_cred.py' /etc/pam.d/common-auth > $(tmpfile)
	cat $(tmpfile) root/etc/pam.d/common-auth > /etc/pam.d/common-auth
	grep -v 'epfl_roaming.py' /etc/pam.d/common-session > $(tmpfile)
	cat $(tmpfile) root/etc/pam.d/common-session > /etc/pam.d/common-session
	rm -f $(tmpfile)
	install -o root -g root -m 755 root/usr/local/bin/manage_cred.py /usr/local/bin
	install -o root -g root -m 755 root/usr/local/bin/epfl_roaming.py /usr/local/bin
	install -o root -g root -m 755 root/usr/local/lib/manage_cred/ext_epfl_roaming.py /usr/local/lib/manage_cred
	install -o root -g root -m 644 root/usr/local/etc/epfl_roaming.conf /usr/local/etc
	install -o root -g root -m 644 root/etc/skel/.config/autostart/epfl_roaming.desktop /etc/skel/.config/autostart
	install -o root -g root -m 644 root/etc/systemd/system/epfl_roaming_on_shutdown.service /etc/systemd/system
	systemctl enable epfl_roaming_on_shutdown.service
