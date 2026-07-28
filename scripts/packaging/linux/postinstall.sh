#!/bin/sh
set -eu
binary=/opt/asvp-agent/asvp-agent
config=/etc/asvp-agent/config.json
enrollment_file=/etc/asvp-agent/enrollment
chmod 0755 "$binary"
mkdir -p /opt/asvp-agent/var
chmod 0700 /opt/asvp-agent/var

server_url=${ASVP_SERVER_URL:-}
enrollment_token=${ASVP_ENROLLMENT_TOKEN:-}
if [ -f "$enrollment_file" ]; then
  server_url=$(sed -n '1p' "$enrollment_file")
  enrollment_token=$(sed -n '2p' "$enrollment_file")
fi

if [ -n "$server_url" ] && [ -n "$enrollment_token" ]; then
  input_file=$(mktemp /etc/asvp-agent/enrollment.XXXXXX)
  chmod 0600 "$input_file"
  printf '%s\n%s\n' "$server_url" "$enrollment_token" > "$input_file"
  "$binary" --config "$config" enroll --input-file "$input_file"
  rm -f "$input_file" "$enrollment_file"
  printf '%s\n' 'ASVP Agent enrollment saved. Installing and starting its systemd service now.'
  "$binary" --config "$config" service install
else
  printf '%s\n' \
    'ASVP Agent installed but not started because enrollment information is missing.' \
    'Set both ASVP_SERVER_URL and ASVP_ENROLLMENT_TOKEN during installation, or place the server URL and token on separate lines in /etc/asvp-agent/enrollment before installation.' \
    'Manual setup:' \
    '  sudo /opt/asvp-agent/asvp-agent --config /etc/asvp-agent/config.json enroll' \
    '  sudo /opt/asvp-agent/asvp-agent --config /etc/asvp-agent/config.json service install'
fi
