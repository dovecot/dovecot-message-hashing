#!/usr/bin/env bash
ulimit -c unlimited
dovecot
cat /dovecot/test.eml | doveadm save -u testuser

if ! grep '"event":"message_hashing_msg_part".*"hash":"7b4758d4baa20873585b9597c7cb9ace2d690ab8"' /var/log/dovecot.log ; then
	echo "ERROR: Could not find msg_part event"
	exit 1
fi

if ! grep '"event":"message_hashing_msg_full".*"hash":"37c1b21b2331c14652305a74d34b45f09ab703d1"' /var/log/dovecot.log ; then
	echo "ERROR: Could not find msg_full event"
	exit 1
fi
