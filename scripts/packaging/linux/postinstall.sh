#!/bin/sh
set -eu
chmod 0755 /opt/asvp-agent/asvp-agent
mkdir -p /opt/asvp-agent/var
chmod 0700 /opt/asvp-agent/var
config=/etc/asvp-agent/config.json
if grep -q 'management\.example\.invalid' "$config"; then
  printf '%s\n' 'ASVP Agent installed.' 'Enroll it with your management server, then install the service:' '  sudo /opt/asvp-agent/asvp-agent --config /etc/asvp-agent/config.json enroll' '  sudo /opt/asvp-agent/asvp-agent --config /etc/asvp-agent/config.json service install'
else
  printf '%s\n' 'ASVP Agent installed with a preconfigured management server.' 'Installing and starting its systemd service now.'
  /opt/asvp-agent/asvp-agent --config "$config" service install
fi
