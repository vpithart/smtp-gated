#!/bin/bash

# make || exit 1

strip src/smtp-gated || exit 1
chmod 755 src/smtp-gated || exit 1
chown root:root src/smtp-gated || exit 1

mv src/smtp-gated /usr/local/sbin/ || exit 1
/etc/init.d/smtp-gated restart

