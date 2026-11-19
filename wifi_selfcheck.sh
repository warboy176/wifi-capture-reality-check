#!/usr/bin/env bash
# wifi_selfcheck.sh -- WiFi Capture Reality Check, Linux self-check.
#
# Checks THIS machine only, and only reads. It reports:
#   1. who is running it, and with which privileges
#   2. your wireless interfaces: driver, bus, current mode, monitor-mode support
#   3. who on this machine can capture packets without root
#   4. whether ordinary users can write to the adapter's device files
#
# It never changes an interface, never scans, never captures, never transmits and never
# asks for root. Every external program it runs goes through ro() below, which refuses
# anything that is not on its short read-only list. Read ro() first.
#
# Usage:  bash wifi_selfcheck.sh        (as your normal user; root is not needed)
# Exit:   0 = nothing flagged, 3 = at least one [FLAG] line
# MIT licence. https://github.com/warboy176/wifi-capture-reality-check

set -u
export LC_ALL=C

# ------------------------------------------------------------------ the read-only guard
# The only external programs this script may run. For iw, only its "show me" forms:
#   iw dev  |  iw dev <interface> info  |  iw phy <phy> info
ro() {
  case "$1" in
    id|stat|readlink|getcap|getfacl) ;;
    iw)
      if   [ "$#" -eq 2 ] && [ "$2" = "dev" ]; then :
      elif [ "$#" -eq 4 ] && [ "$2" = "dev" ] && [ "$4" = "info" ]; then :
      elif [ "$#" -eq 4 ] && [ "$2" = "phy" ] && [ "$4" = "info" ]; then :
      else echo "ro: refused 'iw ${*:2}' (not a read-only form)" >&2; return 99
      fi ;;
    *) echo "ro: refused '$1' (not on the read-only list)" >&2; return 99 ;;
  esac
  command -v "$1" >/dev/null 2>&1 || return 127
  "$@" 2>/dev/null
}

# first line of a (sysfs) file, using shell builtins only
rd() { local l=""; [ -r "$1" ] && IFS= read -r l < "$1"; printf '%s' "$l"; }

FLAGS=0
say()  { printf '%s\n' "$*"; }
ok()   { printf '  [ok]   %s\n' "$*"; }
info() { printf '  [info] %s\n' "$*"; }
flag() { printf '  [FLAG] %s\n' "$*"; FLAGS=$((FLAGS + 1)); }

say "WiFi Capture Reality Check -- Linux self-check (read-only)"
say ""

# ------------------------------------------------------------------ 1. who is running this
say "== 1. Who is running this"
ME=$(ro id -un); MYUID=$(ro id -u); MYGROUPS=$(ro id -Gn)
info "user: ${ME:-?} (uid ${MYUID:-?})"
info "groups: ${MYGROUPS:-?}"

CAPEFF=""
while IFS=$'\t ' read -r k v _; do [ "$k" = "CapEff:" ] && CAPEFF=$v; done < /proc/$$/status
has_cap() { [ -n "$CAPEFF" ] && (( (16#$CAPEFF >> $1) & 1 )); }   # 12 = CAP_NET_ADMIN, 13 = CAP_NET_RAW

if [ "${MYUID:-}" = "0" ]; then
  info "You are root. Root can always capture and change radio modes, so this report mostly"
  info "tells you what OTHER, non-root accounts could do. Run it as your normal user too."
elif has_cap 13 || has_cap 12; then
  info "This shell holds network capabilities (CapEff $CAPEFF): it can capture and/or reconfigure"
  info "interfaces without being root. Check how it got them."
else
  ok "Normal user without network capabilities. That is the safe default."
fi

# ------------------------------------------------------------------ 2. wireless interfaces
say ""
say "== 2. Wireless interfaces on this machine"
WIFS=()
for d in /sys/class/net/*; do
  [ -e "$d/wireless" ] || [ -e "$d/phy80211" ] || continue
  WIFS+=("${d##*/}")
done

monitor_support() {   # prints yes / no / unknown for one phy
  local out line in_modes=0
  out=$(ro iw phy "$1" info) || { echo unknown; return; }
  while IFS= read -r line; do
    if [[ $line == *"Supported interface modes:"* ]]; then in_modes=1; continue; fi
    if (( in_modes )); then
      if [[ $line =~ ^[[:space:]]+\*[[:space:]]+(.+)$ ]]; then
        [ "${BASH_REMATCH[1]}" = "monitor" ] && { echo yes; return; }
      else
        in_modes=0
      fi
    fi
  done <<< "$out"
  echo no
}

SUMMARY_IFS=()
if [ "${#WIFS[@]}" -eq 0 ]; then
  info "No wireless interfaces found. Nothing radio-related to check on this machine."
fi
HAVE_IW=yes; command -v iw >/dev/null 2>&1 || HAVE_IW=no
for i in "${WIFS[@]}"; do
  d=/sys/class/net/$i
  drv=$(ro readlink -f "$d/device/driver"); drv=${drv##*/}
  bus=$(ro readlink -f "$d/device/subsystem"); bus=${bus##*/}
  phy=$(rd "$d/phy80211/name")
  mode=""
  while read -r a b _; do [ "$a" = "type" ] && mode=$b; done <<< "$(ro iw dev "$i" info)"
  if [ -z "$mode" ]; then
    case "$(rd "$d/type")" in 803) mode="monitor" ;; 1) mode="managed" ;; *) mode="unknown" ;; esac
  fi
  mon=unknown; [ -n "$phy" ] && mon=$(monitor_support "$phy")
  info "$i: driver ${drv:-unknown}, bus ${bus:-virtual/unknown}, radio ${phy:-?}, current mode: $mode"
  case "$mon" in
    yes) info "   monitor mode: SUPPORTED by this driver (switching to it still needs root or CAP_NET_ADMIN)" ;;
    no)  info "   monitor mode: not listed by this driver" ;;
    *)   if [ "$HAVE_IW" = no ]; then info "   monitor mode: unknown (install the 'iw' package; this script only uses its read-only forms)"
         else info "   monitor mode: unknown"; fi ;;
  esac
  [ "$mode" = "monitor" ] && info "   $i is in monitor mode RIGHT NOW. If you did not do that, find out what did."
  SUMMARY_IFS+=("$i ($drv, ${bus:-?}): mode $mode, monitor support $mon")
done

# ------------------------------------------------------------------ 3. who can capture
say ""
say "== 3. Who can capture packets on this machine"
CAN_CAPTURE="no"
if [ "${MYUID:-}" = "0" ]; then CAN_CAPTURE="yes (you are root)"
elif has_cap 13; then CAN_CAPTURE="yes (this shell holds CAP_NET_RAW)"; fi
if [ "$CAN_CAPTURE" = "no" ]; then
  ok "You cannot capture by yourself (no root, no CAP_NET_RAW). Capture needs one of those."
else
  info "You can capture: $CAN_CAPTURE."
fi

seen=" "
for t in /usr/bin/dumpcap /usr/sbin/dumpcap /usr/local/bin/dumpcap /usr/bin/tcpdump /usr/sbin/tcpdump /usr/local/sbin/tcpdump; do
  [ -e "$t" ] || continue
  real=$(ro readlink -f "$t"); [ -n "$real" ] || continue
  [[ $seen == *" $real "* ]] && continue; seen+="$real "
  caps=$(ro getcap "$real"); caps=${caps#"$real"}; caps=${caps# }; caps=${caps#= }
  read -r m own grp <<< "$(ro stat -c '%a %U %G' "$real")"
  [ -n "${m:-}" ] || continue
  suid=no; (( 8#$m & 04000 )) && [ "$own" = "root" ] && suid=yes
  if [[ $caps != *cap_net_raw* ]] && [ "$suid" = no ]; then
    ok "$real: no special privileges, so only root can capture with it."
    continue
  fi
  how="file capabilities ($caps)"; [ "$suid" = yes ] && how="setuid root"
  if (( 8#$m & 1 )); then
    flag "$real has $how and ANY local account may run it (mode $m). Every user on this machine can capture."
    CAN_CAPTURE="yes (every local user, via ${real##*/})"
  elif [ -x "$real" ]; then
    info "$real has $how and YOU may run it (group '$grp'), so you can capture without root."
    info "   This is the documented 'allow non-root users to capture' install option. Fine if you chose it."
    [ "${MYUID:-}" != "0" ] && CAN_CAPTURE="yes (via ${real##*/}, group '$grp')"
  else
    ok "$real has $how, but only group '$grp' may run it and you are not in it."
  fi
  if [[ $caps == *cap_net_admin* ]] || [ "$suid" = yes ]; then
    info "   It also holds CAP_NET_ADMIN, which lets whoever runs it switch a supporting radio to monitor mode."
  fi
done
[ "$seen" = " " ] && ok "No dumpcap or tcpdump found in the usual places."

for g in wireshark pcap; do
  [[ " ${MYGROUPS:-} " == *" $g "* ]] && info "You are in group '$g'. On most distributions that is the 'may capture packets' group."
done
[[ " ${MYGROUPS:-} " == *" plugdev "* ]] && info "You are in group 'plugdev'. Some distributions' udev rules give it raw access to USB gadgets (see section 4)."

# ------------------------------------------------------------------ 4. device files
say ""
say "== 4. Can ordinary users write to the adapter's device files?"
DEVFLAGS_BEFORE=$FLAGS
[ "${#WIFS[@]}" -eq 0 ] && ok "No wireless adapters, so no adapter device files to check."

check_node() {   # <path> <what it is>
  local p=$1 what=$2 meta m own grp acl="" typ name perm
  meta=$(ro stat -L -c '%a %U %G' "$p") || { info "$what: $p (could not read its permissions)"; return; }
  read -r m own grp <<< "$meta"
  while IFS=: read -r typ name perm; do
    if [ -n "$name" ] && { [ "$typ" = user ] || [ "$typ" = group ]; }; then acl+=" $typ:$name:$perm"; fi
  done <<< "$(ro getfacl -cp "$p")"
  if (( 8#$m & 2 )); then
    flag "$what: $p is writable by EVERY local account (mode $m $own:$grp). That is the real 'wide open, no admin' case. Fix the udev rule or driver default that set it, and tell the vendor if it came from them."
  elif [ "${MYUID:-}" != "0" ] && [ -w "$p" ]; then
    info "$what: $p is writable by YOU (mode $m $own:$grp${acl:+, ACL:$acl}), through a group or a desktop-session ACL. Common on desktops; worth knowing."
  else
    ok "$what: $p is writable only by its owner/group (mode $m $own:$grp${acl:+, ACL:$acl})."
  fi
}

for i in "${WIFS[@]}"; do
  dev=$(ro readlink -f "/sys/class/net/$i/device") || dev=""
  [ -n "$dev" ] || { info "$i: no hardware device behind it (virtual interface)."; continue; }
  bus=$(ro readlink -f "$dev/subsystem"); bus=${bus##*/}
  case "$bus" in
    usb)
      u=$dev
      while [ "$u" != "/" ] && [ -n "$u" ] && [ ! -e "$u/busnum" ]; do u=${u%/*}; done
      bn=$(rd "$u/busnum"); dn=$(rd "$u/devnum")
      if [ -n "$bn" ] && [ -n "$dn" ]; then
        check_node "$(printf '/dev/bus/usb/%03d/%03d' "$bn" "$dn")" "$i raw USB device node"
      fi ;;
    pci)
      for f in config resource0 resource1 resource2 rom remove reset; do
        [ -e "$dev/$f" ] && check_node "$dev/$f" "$i PCI '$f'"
      done ;;
    *) info "$i: bus '${bus:-unknown}', no raw device node checks for this bus." ;;
  esac
  for f in "/sys/class/net/$i"/* "$dev"/*; do
    [ -f "$f" ] || continue
    m=$(ro stat -c '%a' "$f") || continue
    [ -n "$m" ] && (( 8#$m & 2 )) && flag "world-writable sysfs file: $f (mode $m)"
  done
done

if [ -e /dev/rfkill ]; then
  check_node /dev/rfkill "radio on/off switch"
  info "   (rfkill can switch radios on or off. It cannot capture anything.)"
fi
if [ "${MYUID:-}" != "0" ] && [ -r /sys/kernel/debug/ieee80211 ]; then
  flag "/sys/kernel/debug/ieee80211 is readable by you: the kernel's WiFi debug files are exposed to non-root."
fi
DEVFLAGS=$((FLAGS - DEVFLAGS_BEFORE))

# ------------------------------------------------------------------ summary
say ""
say "== Summary"
say "  Wireless interfaces: ${#WIFS[@]}"
for s in "${SUMMARY_IFS[@]}"; do say "    - $s"; done
say "  This account can capture packets: $CAN_CAPTURE"
say "  Device files writable by every account: $([ "$DEVFLAGS" -eq 0 ] && echo none found || echo "$DEVFLAGS finding(s)")"
say "  FLAGS: $FLAGS"
say ""
say "What this means:"
say "  - 'Monitor mode: SUPPORTED' is a normal, documented driver feature. Turning it on needs root"
say "    (or a capture tool you deliberately allowed). Nothing here 'unlocks' anything."
say "  - Capturing without root is possible only if this machine was set up to allow it, usually"
say "    the Wireshark 'non-superusers may capture' option. That is a choice, not a hack."
say "  - A [FLAG] means a real weakening of the defaults. Fix it locally, and report it to the"
say "    vendor if it shipped that way. That is a bug report, not an AI superpower."
say "  - Only capture on networks and devices you own or are allowed to test."
[ "$FLAGS" -eq 0 ] && exit 0 || exit 3
