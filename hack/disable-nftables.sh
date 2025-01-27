#!/bin/bash
set -x
# Remediation is applicable only in certain platforms
if ( dpkg-query --show --showformat='${db:Status-Status}\n' 'firewalld' 2>/dev/null | grep -q installed && dpkg-query --show --showformat='${db:Status-Status}\n' 'nftables' 2>/dev/null | grep -q installed  ); then
# && dpkg-query --show --showformat='${db:Status-Status}' 'kernel' 2>/dev/null | grep -q installed
SYSTEMCTL_EXEC='/usr/bin/systemctl'
"$SYSTEMCTL_EXEC" stop 'nftables.service'
"$SYSTEMCTL_EXEC" disable 'nftables.service'
"$SYSTEMCTL_EXEC" mask 'nftables.service'
# Disable socket activation if we have a unit file for it
if "$SYSTEMCTL_EXEC" -q list-unit-files nftables.socket; then
    "$SYSTEMCTL_EXEC" stop 'nftables.socket'
    "$SYSTEMCTL_EXEC" mask 'nftables.socket'
fi
# The service may not be running because it has been started and failed,
# so let's reset the state so OVAL checks pass.
# Service should be 'inactive', not 'failed' after reboot though.
"$SYSTEMCTL_EXEC" reset-failed 'nftables.service' || true
"$SYSTEMCTL_EXEC" status 'nftables.socket'
else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi