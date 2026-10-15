#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT=/opt/relaydeck
DATA=/var/lib/relaydeck
REPO=321CMO/relaydeck
VERSION=v0.1.0-alpha.2
ARTIFACT=
DOMAIN=
ENDPOINT=
SERVER_ID=
ROLE=
UNIT_DIR=/etc/systemd/system
STAGE=
WORK_DIR=
if ! declare -F upgrade_transaction >/dev/null; then
 source "${BASH_SOURCE[0]%/*}/lib/lifecycle.sh"
fi
die(){ printf '错误：%s\n' "$*" >&2; exit 1; }
need_root(){ [[ $EUID -eq 0 ]] || die '请用 sudo 运行管理脚本'; [[ $(uname -s) == Linux ]] || die '安装器仅支持 Linux systemd'; command -v systemctl >/dev/null || die '需要 systemd'; }
usage(){ cat <<'EOF'
RelayDeck 开发安装器
  install panel --domain panel.example.com [--version vX.Y.Z | --artifact 已校验的包.tar.gz]
  install agent --endpoint https://panel.example.com --server srv_x [--version vX.Y.Z | --artifact 包.tar.gz]
  upgrade panel|agent --version vX.Y.Z
  rollback panel|agent
  status | logs panel|agent | setup-code | reset-password | backup 文件 | restore 文件
  repair-https | uninstall panel|agent
安装前必须已有通过验证的 Release，或显式提供自己构建的可信开发包。
卸载默认保留数据；不会删除其他防火墙表或云安全组规则。
同机中心与 Agent 共用程序，升级会一起切换版本；手动回退程序保留现有数据。
EOF
}
parse(){ while (($#)); do [[ $# -ge 2 ]] || die "参数缺少值：$1"; case "$1" in --version) VERSION=$2;; --artifact) ARTIFACT=$2;; --domain) DOMAIN=$2;; --endpoint) ENDPOINT=$2;; --server) SERVER_ID=$2;; *) die "未知参数：$1";; esac; shift 2; done; }
valid_role(){ [[ $ROLE == panel || $ROLE == agent ]] || die '角色应为 panel 或 agent'; }
deps(){ command -v apt-get >/dev/null || die '开发安装器目前支持 Debian/Ubuntu'; apt-get update -qq; apt-get install -y -qq ca-certificates curl tar coreutils nftables python3 util-linux iproute2; }
package(){
 local arch work archive checksum actual
 case $(uname -m) in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; *) die '仅支持 amd64/arm64';; esac
 [[ $VERSION =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$ ]] || die '版本号无效'
 work=$(mktemp -d -t relaydeck-install.XXXXXXXX); WORK_DIR=$work; archive="$work/package.tar.gz"
 if [[ -n $ARTIFACT ]]; then [[ -f $ARTIFACT ]] || die '开发包不存在'; cp "$ARTIFACT" "$archive"
 else
  curl --fail --location --proto '=https' --tlsv1.2 --retry 2 "https://github.com/$REPO/releases/download/$VERSION/relaydeck-linux-$arch.tar.gz" --output "$archive" || die '该 Release 尚不存在或下载失败；当前项目仍在开发'
  curl --fail --location --proto '=https' --tlsv1.2 "https://github.com/$REPO/releases/download/$VERSION/SHA256SUMS" --output "$work/SHA256SUMS"
  checksum=$(awk -v name="relaydeck-linux-$arch.tar.gz" '$2==name {print $1}' "$work/SHA256SUMS"); [[ $checksum =~ ^[0-9a-f]{64}$ ]] || die '校验清单无效'
  actual=$(sha256sum "$archive"); [[ ${actual%% *} == "$checksum" ]] || die '下载文件校验失败'
 fi
 # Only controlled regular executables and optional upstream license files are accepted.
 local names name; names=$(tar -tzf "$archive" | sort)
 [[ -z $(printf '%s\n' "$names" | uniq -d) ]] || die '安装包包含重复文件'
 for name in caddy relaydeck sing-box; do [[ $'\n'"$names"$'\n' == *$'\n'"$name"$'\n'* ]] || die '安装包缺少核心程序'; done
 while IFS= read -r name; do case $name in caddy|relaydeck|sing-box|CADDY-LICENSE.txt|SING-BOX-LICENSE.txt) :;; *) die '安装包文件清单无效';; esac; done <<< "$names"
 [[ $(tar -tvzf "$archive" | awk 'substr($1,1,1)!="-" {n++} END {print n+0}') == 0 ]] || die '安装包包含链接或非普通文件'
 STAGE="$work/unpacked"; mkdir "$STAGE"; tar --extract --gzip --file "$archive" --directory "$STAGE" --no-same-owner --no-same-permissions
 chmod 0755 "$STAGE/relaydeck" "$STAGE/sing-box" "$STAGE/caddy"; "$STAGE/relaydeck" version >/dev/null; "$STAGE/sing-box" version >/dev/null; "$STAGE/caddy" version >/dev/null
}
install_files(){
 stage_bundle || die '程序包暂存失败，原程序未切换。旧开发安装布局需要先手动迁移。'
 if [[ -L $ROOT/current ]]; then
  local name
  for name in relaydeck sing-box caddy; do cmp -s "$STAGE/$name" "$ROOT/current/$name" || die '同机已有其他角色且版本不同，请先使用 upgrade 更新共用程序'; done
 else
  activate_bundle "$NEW_BUNDLE" || die '程序版本激活失败'
 fi
 mkdir -p "$DATA/panel" "$DATA/agent"; chmod 0755 "$DATA"; chmod 0700 "$DATA/panel" "$DATA/agent"
}
units(){
 if [[ $ROLE == panel ]]; then
  [[ $DOMAIN =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+[a-zA-Z0-9]$ && $DOMAIN == *.* && $DOMAIN != *..* ]] || die '请输入完整域名，不要包含协议、路径或端口'
  id relaydeck >/dev/null 2>&1 || useradd --system --user-group --home-dir "$DATA" --shell /usr/sbin/nologin relaydeck
  "$ROOT/bin/relaydeck" bootstrap-https --data "$DATA/panel" --url "https://$DOMAIN"
  chown -R relaydeck:relaydeck "$DATA/panel"; mkdir -p "$DATA/caddy"; chown relaydeck:relaydeck "$DATA/caddy"
  if [[ ! -f $DATA/panel/Caddyfile ]]; then
   bootstrap_caddyfile "$DOMAIN" > "$DATA/panel/Caddyfile"
  fi
  chown relaydeck:relaydeck "$DATA/panel/Caddyfile"
  cat > $UNIT_DIR/relaydeck-panel.service <<EOF
# Managed by RelayDeck
[Unit]
Description=RelayDeck Panel
After=network-online.target
Wants=network-online.target
[Service]
User=relaydeck
Group=relaydeck
ExecStart=$ROOT/bin/relaydeck serve --data $DATA/panel --url https://$DOMAIN
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$DATA/panel
ProtectHome=true
[Install]
WantedBy=multi-user.target
EOF
  cat > $UNIT_DIR/relaydeck-caddy.service <<EOF
# Managed by RelayDeck
[Unit]
Description=RelayDeck HTTPS
After=network-online.target relaydeck-panel.service
[Service]
User=relaydeck
Group=relaydeck
Environment=XDG_DATA_HOME=$DATA/caddy
Environment=XDG_CONFIG_HOME=$DATA/caddy
ExecStart=$ROOT/core/caddy run --resume --config $DATA/panel/Caddyfile --adapter caddyfile
Restart=on-failure
RestartSec=5
UMask=0077
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=$DATA/caddy $DATA/panel
ProtectHome=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF
 else
  [[ $ENDPOINT =~ ^https://[a-zA-Z0-9.-]+(:[0-9]+)?/?$ ]] || die '请输入中心 HTTPS 地址'
  [[ $SERVER_ID =~ ^srv_[a-zA-Z0-9_-]+$ ]] || die '服务器 ID 无效'
  "$ROOT/bin/relaydeck" enroll --data "$DATA/agent" --endpoint "$ENDPOINT" --server "$SERVER_ID"
  cat > $UNIT_DIR/relaydeck-agent.service <<EOF
# Managed by RelayDeck
[Unit]
Description=RelayDeck Agent and sing-box
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=$ROOT/bin/relaydeck agent --data $DATA/agent --core $ROOT/core/sing-box
Restart=on-failure
RestartSec=5
UMask=0077
ProtectSystem=strict
ReadWritePaths=$DATA/agent
ProtectHome=true
PrivateTmp=true
KillMode=control-group
[Install]
WantedBy=multi-user.target
EOF
 fi
 systemctl daemon-reload; systemctl enable --now "relaydeck-$ROLE"; if [[ $ROLE == panel ]]; then systemctl enable --now relaydeck-caddy; service_ready relaydeck-caddy || die 'HTTPS 服务未通过运行检查，请诊断 relaydeck-caddy'; fi
}
cleanup(){ if [[ -n $WORK_DIR && ${WORK_DIR##*/} == relaydeck-install.* ]]; then rm -rf -- "$WORK_DIR"; fi; }
validate_install_args(){
 if [[ $ROLE == panel ]]; then
  [[ $DOMAIN =~ ^[a-zA-Z0-9][a-zA-Z0-9.-]+[a-zA-Z0-9]$ && $DOMAIN == *.* && $DOMAIN != *..* ]] || die '请输入完整域名，不要包含协议、路径或端口'
 else
  [[ $ENDPOINT =~ ^https://[a-zA-Z0-9.-]+(:[0-9]+)?/?$ ]] || die '请输入中心 HTTPS 地址'
  [[ $SERVER_ID =~ ^srv_[a-zA-Z0-9_-]+$ ]] || die '服务器 ID 无效'
 fi
}
check_owned_units(){
 local unit
 for unit in "${managed_units[@]}"; do
  if [[ -e $UNIT_DIR/$unit.service ]]; then
   [[ $(head -n 1 "$UNIT_DIR/$unit.service") == '# Managed by RelayDeck' ]] || die "服务名被其他程序占用：$unit"
  fi
 done
}
main(){
 local cmd=${1:-help}; shift || true
 case $cmd in
 help|--help|-h) usage; return;;
 install|upgrade|rollback|logs|uninstall) ROLE=${1:-}; [[ $# -gt 0 ]] && shift; valid_role;;
 esac
 need_root
 command -v flock >/dev/null || die '需要 util-linux 提供 flock'
 exec 9>/run/lock/relaydeck.install.lock
 flock -n 9 || die '另一项安装或升级操作正在运行'
 trap cleanup EXIT
 check_owned_units
 if [[ $cmd != status && $cmd != logs ]]; then recover_interrupted_upgrade || die '上次升级恢复失败，请保留快照并检查服务'; fi
 case $cmd in
 install) parse "$@"; validate_install_args; if [[ -f $UNIT_DIR/relaydeck-$ROLE.service ]] && systemctl is-active --quiet "relaydeck-$ROLE"; then die '该角色已安装，请使用 upgrade'; fi; deps; package; install_files; units; service_ready "relaydeck-$ROLE" || die '服务未通过运行检查，数据和程序已保留，可诊断后重试'; printf '服务已安装。Agent 注册与证书签发状态请在面板核对。\n'; if [[ $ROLE == panel ]]; then if [[ -f $DATA/panel/bootstrap.txt ]]; then printf '首次设置码：'; cat "$DATA/panel/bootstrap.txt"; printf '\n'; fi; printf '面板：https://%s\n设置码过期可运行 setup-code。\n' "$DOMAIN"; fi;;
 upgrade) parse "$@"; [[ -f $UNIT_DIR/relaydeck-$ROLE.service ]] || die '尚未安装该角色'; package; stage_bundle || die '程序包暂存失败'; printf '同机 RelayDeck 服务共用程序，将一起切换版本；正在创建本机私有快照。\n'; if ! upgrade_transaction; then die '升级未通过检查，已尝试恢复原程序和升级前数据；请检查服务状态'; fi; printf '升级完成，本机回退快照：%s\n' "$SNAPSHOT";;
 rollback) [[ -f $UNIT_DIR/relaydeck-$ROLE.service ]] || die '尚未安装该角色'; rollback_program || die '旧程序未通过运行检查，已尝试恢复当前程序；数据未自动回退'; printf '已回退程序，现有面板数据保持不变。\n';;

 status) systemctl --no-pager --full status relaydeck-panel relaydeck-agent relaydeck-caddy;;
 logs) journalctl --no-pager -u "relaydeck-$ROLE" -n 100;;
 setup-code|reset-password) systemctl stop relaydeck-panel; if ! "$ROOT/bin/relaydeck" "$cmd" --data "$DATA/panel"; then systemctl start relaydeck-panel; die '操作失败'; fi; systemctl start relaydeck-panel;;
 backup|restore) local file=${1:-}; [[ -n $file ]] || die '请指定文件路径'; systemctl stop relaydeck-panel; if ! "$ROOT/bin/relaydeck" "$cmd" --data "$DATA/panel" --file "$file"; then systemctl start relaydeck-panel; die '备份或恢复失败'; fi; chown -R relaydeck:relaydeck "$DATA/panel"; systemctl start relaydeck-panel;;
 repair-https) "$ROOT/core/caddy" validate --config "$DATA/panel/Caddyfile" --adapter caddyfile; systemctl restart relaydeck-caddy; printf '已重启 HTTPS。诊断：journalctl -u relaydeck-caddy\n';;
 uninstall) systemctl disable --now "relaydeck-$ROLE"; rm -f "$UNIT_DIR/relaydeck-$ROLE.service"; if [[ $ROLE == panel ]]; then systemctl disable --now relaydeck-caddy; rm -f "$UNIT_DIR/relaydeck-caddy.service"; elif command -v nft >/dev/null; then nft delete table inet relaydeck 2>/dev/null || true; fi; systemctl daemon-reload; printf '服务已卸载，数据保留在 %s。请同时在中心移除该服务器的授权。\n' "$DATA";;
 *) die '未知命令，请运行 help';;
 esac
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then main "$@"; fi
