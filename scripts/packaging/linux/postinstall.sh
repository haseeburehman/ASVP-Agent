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

if [ -n "$server_url" ]; then
  input_file=$(mktemp /etc/asvp-agent/enrollment.XXXXXX)
  chmod 0600 "$input_file"
  printf '%s\n%s\n' "$server_url" "$enrollment_token" > "$input_file"
  "$binary" --config "$config" enroll --input-file "$input_file"
  rm -f "$input_file" "$enrollment_file"
  printf '%s\n' 'ASVP Agent enrollment saved. Installing and starting its systemd service now.'
  (cd /opt/asvp-agent && "$binary" --config "$config" integrity rebaseline)
  "$binary" --config "$config" service install
elif ! grep -q 'management\.example\.invalid' "$config"; then
  rm -f "$enrollment_file"
  printf '%s\n' 'ASVP Agent installed with a baked management server URL. Installing and starting its systemd service now.'
  (cd /opt/asvp-agent && "$binary" --config "$config" integrity rebaseline)
  "$binary" --config "$config" service install
else
  (cd /opt/asvp-agent && "$binary" --config "$config" integrity rebaseline)
  printf '%s\n' \
    'ASVP Agent installed but not started because no management server URL is configured.' \
    'Set ASVP_SERVER_URL during installation, or place the server URL and optional token on separate lines in /etc/asvp-agent/enrollment before installation.' \
    'ASVP_ENROLLMENT_TOKEN is optional unless the management server enables REQUIRE_ENROLLMENT_TOKEN.' \
    'Manual setup:' \
    '  sudo /opt/asvp-agent/asvp-agent --config /etc/asvp-agent/config.json enroll' \
    '  sudo /opt/asvp-agent/asvp-agent --config /etc/asvp-agent/config.json service install'
fi
