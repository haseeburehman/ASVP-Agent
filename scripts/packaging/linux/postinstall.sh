#!/bin/sh
set -eu
chmod 0755 /opt/asvp-agent/asvp-agent
mkdir -p /opt/asvp-agent/var
chmod 0700 /opt/asvp-agent/var
printf '%s\n' 'ASVP Agent installed.' 'To install and start its systemd service, run:' '  sudo /opt/asvp-agent/asvp-agent --config /etc/asvp-agent/config.json service install'
