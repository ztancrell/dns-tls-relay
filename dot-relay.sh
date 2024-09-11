#!/bin/bash

CONFIG_FILE="/home/$SUDO_USER/.dns-tls-assistant.conf"
INTERFACE_IP_PROMPT="Enter interface IP here (ex. 127.0.0.1): "
DNS_PROVIDER_PROMPT="Enter your preferred primary DNS provider here (ex. 9.9.9.9): "
SECONDARY_DNS_PROMPT="Enter your preferred secondary DNS provider here (ex. 149.112.112.112): "
KEEP_ALIVE_PROMPT="Enter your preferred keep alive here (4, 6 or 8): "
MIN_KEEP_ALIVE=4
MAX_KEEP_ALIVE=8

print_title() {
  printf '\033]2;dns tls relay assistant\a\n'
}

get_dot_relay_dir() {
  DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"/$DOT_RELAY_DIR
}

get_interface_ip() {
  read -rp "$INTERFACE_IP_PROMPT" interface_ip
}

get_dns_providers() {
  read -rp "$DNS_PROVIDER_PROMPT" primary_dns
  read -rp "$SECONDARY_DNS_PROMPT" secondary_dns
}

get_keep_alive() {
  read -rp "$KEEP_ALIVE_PROMPT" keep_alive
}

check_root() {
  if [ "$UID" -gt 0 ]; then
    die "This script must be run as root!" 1
  fi
}

check_keep_alive() {
  if [[ "$keep_alive" -lt $MIN_KEEP_ALIVE || "$keep_alive" -gt $MAX_KEEP_ALIVE ]]; then
   die "Keep alive must be between $MIN_KEEP_ALIVE - $MAX_KEEP_ALIVE!" 1
  fi
}

die() {
  printf '%s\n' "$1"
  exit "${2:-0}"
}

read_config_file() {
    if [ ! -f "$CONFIG_FILE" ]; then
        return
    fi

    while IFS= read -r line; do
        case $line in
            interface_ip=*)
                interface_ip=${line#*=}
                ;;
            primary_dns=*)
                primary_dns=${line#*=}
                ;;
            secondary_dns=*)
                secondary_dns=${line#*=}
                ;;
            keep_alive=*)
                keep_alive=${line#*=}
                ;;
        esac
    done < "$CONFIG_FILE"
}

write_config_file() {
    if [ ! -w "$CONFIG_FILE" ]; then
	sudo chown $USER:$USER "$CONFIG_FILE"
	sudo chmod 755 "$CONFIG_FILE"
        die "Permission denied: $CONFIG_FILE" 1
    fi

    cat <<EOF > "$CONFIG_FILE"
interface_ip=$interface_ip
primary_dns=$primary_dns
secondary_dns=$secondary_dns
keep_alive=$keep_alive
EOF
}

run_relay() {
  cd "$DIR" || die "Could not change to $DOT_RELAY_DIR!"
  python3 ./run_relay.py -l "$interface_ip" -r "$primary_dns" "$secondary_dns" -k "$keep_alive" -c -v
}

main() {
  print_title
  get_dot_relay_dir

  read_config_file

  if [ ! -f "$CONFIG_FILE" ]; then
      get_interface_ip
      get_dns_providers
      get_keep_alive
  fi

  write_config_file

  check_root
  check_keep_alive

  run_relay

  printf "... dns-tls-assistant complete ...\n"
}

main
