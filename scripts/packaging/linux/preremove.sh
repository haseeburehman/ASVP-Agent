#!/bin/sh
set -eu
if [ -x /opt/asvp-agent/asvp-agent ]; then
  /opt/asvp-agent/asvp-agent --config /etc/asvp-agent/config.json service uninstall || true
fi
