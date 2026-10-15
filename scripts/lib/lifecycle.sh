#!/usr/bin/env bash
# Sourced by the installer. No commands run merely by sourcing this library.

managed_units=(relaydeck-panel relaydeck-agent relaydeck-caddy)
running_units=()
SNAPSHOT=

replace_path(){
 python3 - "$1" "$2" <<'PY'
import os, sys
os.replace(sys.argv[1], sys.argv[2])
PY
}
bundle_target(){
 local target; target=$(readlink "$ROOT/current") || return 1
 [[ $target == releases/* && $target != *..* && $target != /* ]] || return 1
 [[ -x $ROOT/$target/relaydeck && -x $ROOT/$target/sing-box && -x $ROOT/$target/caddy ]] || return 1
 printf '%s\n' "$target"
}
activate_bundle(){
 local target=$1
 [[ $target == releases/* && $target != *..* && -d $ROOT/$target ]] || return 1
 rm -f -- "$ROOT/.current.next"
 ln -s "$target" "$ROOT/.current.next" || return 1
 replace_path "$ROOT/.current.next" "$ROOT/current"
}
stage_bundle(){
 local hash target temporary name
 hash=$(for name in relaydeck sing-box caddy; do sha256sum "$STAGE/$name" | awk '{print $1}'; done | sha256sum); hash=${hash%% *}
 target="releases/${VERSION}-${hash:0:16}"
 [[ ! -L $ROOT && ! -L $ROOT/releases ]] || return 1
 mkdir -p "$ROOT/releases" "$ROOT/bin" "$ROOT/core" || return 1
 chmod 0755 "$ROOT" "$ROOT/releases" "$ROOT/bin" "$ROOT/core" || return 1
 if [[ -d $ROOT/$target ]]; then
  for name in relaydeck sing-box caddy; do cmp -s "$STAGE/$name" "$ROOT/$target/$name" || return 1; done
 else
  temporary=$(mktemp -d "$ROOT/releases/.staging.XXXXXXXX") || return 1
  chmod 0755 "$temporary" || return 1
  for name in relaydeck sing-box caddy; do install -m 0755 "$STAGE/$name" "$temporary/$name" || return 1; done
  replace_path "$temporary" "$ROOT/$target" || return 1
 fi
 # Compatibility paths remain stable while the bundle pointer changes atomically.
 for name in relaydeck sing-box caddy; do
  local dest="$ROOT/core/$name"; [[ $name != relaydeck ]] || dest="$ROOT/bin/$name"
  if [[ -e $dest && ! -L $dest ]]; then return 1; fi
  if [[ -L $dest ]]; then [[ $(readlink "$dest") == "../current/$name" ]] || return 1; else ln -s "../current/$name" "$dest" || return 1; fi
 done
 NEW_BUNDLE=$target
}
capture_running(){
 running_units=()
 local unit
 for unit in "${managed_units[@]}"; do
  if [[ -f $UNIT_DIR/$unit.service ]] && systemctl is-active --quiet "$unit"; then running_units+=("$unit"); fi
 done
}
stop_running(){
 local index; for ((index=${#running_units[@]}-1;index>=0;index--)); do systemctl stop "${running_units[index]}" || return 1; done
}
start_running(){
 # Keep the public HTTPS entry stopped until the internal services are ready.
 ((${#running_units[@]})) || return 0
 local unit
 for unit in "${running_units[@]}"; do [[ $unit == relaydeck-caddy ]] || systemctl start "$unit" || return 1; done
 for unit in "${running_units[@]}"; do [[ $unit == relaydeck-caddy ]] || service_ready "$unit" || return 1; done
 for unit in "${running_units[@]}"; do [[ $unit != relaydeck-caddy ]] || { systemctl start "$unit" && service_ready "$unit"; } || return 1; done
}
service_ready(){
 local unit=$1 attempt restarts
 for attempt in {1..15}; do
  if systemctl is-active --quiet "$unit"; then
   restarts=$(systemctl show "$unit" --property=NRestarts --value) || return 1
   sleep 2
   if ! systemctl is-active --quiet "$unit"; then continue; fi
   [[ $(systemctl show "$unit" --property=NRestarts --value) == "$restarts" ]] || return 1
   if [[ $unit != relaydeck-panel ]] || curl --fail --silent --max-time 3 http://127.0.0.1:8787/healthz >/dev/null; then return 0; fi
  fi
  sleep 1
 done
 return 1
}
snapshot_data(){
 local backup_root="$DATA/backups" name target
 target=$(bundle_target) || return 1
 mkdir -p "$backup_root" || return 1; chmod 0700 "$backup_root" || return 1
 SNAPSHOT=$(mktemp -d "$backup_root/upgrade.XXXXXXXX") || return 1
 printf '%s\n' "$target" > "$SNAPSHOT/bundle" || return 1
 : > "$SNAPSHOT/services" || return 1
 if ((${#running_units[@]})); then printf '%s\n' "${running_units[@]}" > "$SNAPSHOT/services" || return 1; fi
 for name in panel agent caddy; do
  [[ ! -L $DATA/$name ]] || return 1
  if [[ -d $DATA/$name ]]; then cp -a "$DATA/$name" "$SNAPSHOT/$name" || return 1; fi
 done
 printf 'complete\n' > "$SNAPSHOT/complete" || return 1
}
restore_snapshot_data(){
 local snapshot=$1 name stage displaced target
 [[ $snapshot == "$DATA/backups/upgrade."* && -f $snapshot/complete ]] || return 1
 target=$(cat "$snapshot/bundle") || return 1
 for name in panel agent caddy; do
  if [[ -d $snapshot/$name ]]; then
   stage=$(mktemp -d "$DATA/.restore-$name.XXXXXXXX") || return 1
   # cp copies into an absent name, preserving the original directory permissions.
   cp -a "$snapshot/$name" "$stage/restored" || return 1
   displaced="$stage/displaced"
   if [[ -e $DATA/$name ]]; then replace_path "$DATA/$name" "$displaced" || return 1; fi
   if ! replace_path "$stage/restored" "$DATA/$name"; then
    [[ ! -e $displaced ]] || replace_path "$displaced" "$DATA/$name"
    return 1
   fi
   rm -rf -- "$stage"
  fi
 done
 activate_bundle "$target"
}
upgrade_transaction(){
 capture_running || return 1
 stop_running || { start_running; return 1; }
 if ! snapshot_data; then start_running; return 1; fi
 # A durable journal makes an interrupted upgrade detectable on the next invocation.
 printf '%s\n' "$SNAPSHOT" > "$ROOT/pending-upgrade" || { start_running; return 1; }
 if activate_bundle "$NEW_BUNDLE" && start_running; then
  if cp "$SNAPSHOT/bundle" "$ROOT/previous-bundle" &&
     printf '%s\n' "$SNAPSHOT" > "$ROOT/last-snapshot" &&
     rm -f -- "$ROOT/pending-upgrade"; then return 0; fi
 fi
 stop_running || true
 if restore_snapshot_data "$SNAPSHOT" && start_running; then rm -f -- "$ROOT/pending-upgrade"; fi
 return 1
}
recover_interrupted_upgrade(){
 local snapshot unit
 [[ -f $ROOT/pending-upgrade ]] || return 0
 snapshot=$(cat "$ROOT/pending-upgrade") || return 1
 [[ $snapshot == "$DATA/backups/upgrade."* && -f $snapshot/services ]] || return 1
 running_units=()
 while IFS= read -r unit; do
  case $unit in relaydeck-panel|relaydeck-agent|relaydeck-caddy) running_units+=("$unit");; '') :;; *) return 1;; esac
 done < "$snapshot/services"
 stop_running || return 1
 restore_snapshot_data "$snapshot" && start_running || return 1
 rm -f -- "$ROOT/pending-upgrade"
}
rollback_program(){
 local old target
 target=$(cat "$ROOT/previous-bundle") || return 1
 old=$(bundle_target) || return 1
 capture_running && stop_running || return 1
 if activate_bundle "$target" && start_running; then return 0; fi
 stop_running || true
 activate_bundle "$old" && start_running || return 1
 return 1
}
