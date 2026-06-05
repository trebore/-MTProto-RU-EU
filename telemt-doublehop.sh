#!/usr/bin/env bash
#
# telemt-doublehop.sh — интерактивная установка double-hop прокси для Telegram
#   Схема:  клиент → A (РФ, HAProxy) → AmneziaWG туннель → B (заграница, telemt) → Telegram
#
#   Запуск 1: на ВЫХОДНОМ сервере B (заграница) — печатает TOKEN.
#   Запуск 2: на ВХОДНОМ  сервере A (РФ)        — вставляешь TOKEN, получаешь ссылку.
#   Повторный запуск на любом сервере → админ-меню.
#
#   Требования: Ubuntu 24.04 (22.04 тоже ок), root.
#
# -e: падаем на ошибках установки; pipefail/-u намеренно НЕ включаем,
# чтобы диагностические пайплайны (пустой grep и т.п.) не роняли админку.
set -e

# ─────────────────────────── константы ───────────────────────────
AWG_DIR="/etc/amnezia/amneziawg"
TELEMT_CFG="/etc/telemt/telemt.toml"
HAPROXY_CFG="/etc/haproxy/haproxy.cfg"
STATE_DIR="/etc/telemt-doublehop"
STATE="$STATE_DIR/params.env"
TUN_NET="10.10.10"        # подсеть туннеля
TUN_A="${TUN_NET}.2"      # вход (A)
TUN_B="${TUN_NET}.1"      # выход (B)
TELEMT_PORT_DEF=4443      # внутренний порт telemt (на туннельном IP, наружу не торчит)
CLIENT_PORT_DEF=2053      # клиентский порт по умолчанию (непопулярный; можно 443)
WG_PORT_DEF=8443          # порт AmneziaWG туннеля (udp)
DOMAIN_DEF="www.microsoft.com"

# ─────────────────────────── оформление ──────────────────────────
c_g="\033[1;32m"; c_y="\033[1;33m"; c_r="\033[1;31m"; c_b="\033[1;36m"; c_0="\033[0m"
say(){ echo -e "${c_b}▸${c_0} $*"; }
ok(){  echo -e "${c_g}✓${c_0} $*"; }
warn(){ echo -e "${c_y}!${c_0} $*"; }
err(){ echo -e "${c_r}✗ $*${c_0}" >&2; }
hr(){ echo "────────────────────────────────────────────────────────"; }

trap 'rc=$?; [ $rc -ne 0 ] && { echo; err "Прервано (код $rc). Существующие сервисы не тронуты — можно перезапустить скрипт."; }' EXIT

# ─────────────────────────── утилиты ──────────────────────────────
need_root(){ [ "$(id -u)" = "0" ] || { err "Запусти от root (sudo -i)."; exit 1; }; }

check_os(){
  . /etc/os-release 2>/dev/null || true
  case "${VERSION_ID:-}" in
    24.04|22.04) : ;;
    *) warn "ОС: ${NAME:-?} ${VERSION_ID:-?}. Скрипт рассчитан на Ubuntu 24.04/22.04 — продолжаем, но возможны нюансы.";;
  esac
}

valid_ip(){ [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }
valid_port(){ [[ "$1" =~ ^[0-9]+$ ]] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]; }

detect_ip(){
  local ip=""
  for u in "https://ifconfig.me" "https://api.ipify.org" "https://ipv4.icanhazip.com"; do
    ip=$(curl -4 -fsS --max-time 6 "$u" 2>/dev/null | tr -d '[:space:]') || true
    valid_ip "$ip" && { echo "$ip"; return 0; }
  done
  return 1
}

port_busy(){ ss -ltnH "( sport = :$1 )" 2>/dev/null | grep -q . || ss -lunH "( sport = :$1 )" 2>/dev/null | grep -q .; }

ask(){ # ask "Вопрос" "default" -> echo ответ
  local q="$1" d="${2:-}" a=""
  if [ -n "$d" ]; then read -rp "$(echo -e "${c_b}?${c_0} $q [$d]: ")" a; echo "${a:-$d}"
  else read -rp "$(echo -e "${c_b}?${c_0} $q: ")" a; echo "$a"; fi
}

rint(){ echo $(( (RANDOM*32768 + RANDOM) % ($2-$1+1) + $1 )); }   # случайное в [lo, hi]

gen_obfs(){ # генерим уникальные параметры обфускации (общие для A и B)
  OBF_JC=$(rint 4 9); OBF_JMIN=$(rint 25 50); OBF_JMAX=$((OBF_JMIN + $(rint 30 120)))
  OBF_S1=$(rint 20 120); OBF_S2=$(rint 20 120)
  [ "$OBF_S2" -eq "$((OBF_S1+56))" ] && OBF_S2=$((OBF_S2+1))   # запрет S1+56==S2
  local -a H=(); local i v
  while [ "${#H[@]}" -lt 4 ]; do
    v=$(rint 100 2000000000); local dup=0
    for x in "${H[@]:-}"; do [ "$x" = "$v" ] && dup=1; done
    [ "$dup" = 0 ] && H+=("$v")
  done
  OBF_H1=${H[0]}; OBF_H2=${H[1]}; OBF_H3=${H[2]}; OBF_H4=${H[3]}
}

domain_hex(){ printf '%s' "$1" | od -An -tx1 | tr -d ' \n'; }
mk_link(){ echo "tg://proxy?server=${1}&port=${2}&secret=ee${3}$(domain_hex "$4")"; }

# ─────────────────────────── установка AmneziaWG ──────────────────
install_awg(){
  command -v awg >/dev/null 2>&1 && modprobe amneziawg 2>/dev/null && lsmod | grep -q amneziawg && { ok "AmneziaWG уже установлен."; return 0; }
  say "Ставлю AmneziaWG (PPA + модуль ядра)…"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq software-properties-common python3-launchpadlib gnupg2 "linux-headers-$(uname -r)" >/dev/null
  add-apt-repository -y ppa:amnezia/ppa >/dev/null 2>&1
  apt-get update -qq
  apt-get install -y -qq amneziawg >/dev/null
  if ! modprobe amneziawg 2>/dev/null || ! lsmod | grep -q amneziawg; then
    err "Модуль ядра amneziawg не загрузился (DKMS под $(uname -r) не собрался)."
    err "Проверь: dkms status; apt-get install --reinstall amneziawg"
    exit 1
  fi
  ok "AmneziaWG установлен, модуль ядра загружен."
}

free_awg_iface(){ for n in 0 1 2 3 4; do ip link show "awg$n" >/dev/null 2>&1 || { echo "awg$n"; return; }; done; echo "awg0"; }

# ─────────────────────────── РОЛЬ: ВЫХОД (B) ──────────────────────
setup_exit(){
  hr; say "Настройка ВЫХОДНОГО сервера (заграница, telemt)"; hr

  local B_IP ENTRY_IP CLIENT_PORT WG_PORT DOMAIN TELEMT_PORT TUN_IF SECRET
  B_IP=$(detect_ip || true)
  if valid_ip "${B_IP:-}"; then ok "Мой публичный IP: $B_IP"
  else B_IP=$(ask "Не смог определить мой публичный IP. Введи публичный IP ЭТОГО (выходного) сервера"); fi
  valid_ip "$B_IP" || { err "Некорректный IP."; exit 1; }

  ENTRY_IP=$(ask "Публичный IP ВХОДНОГО (РУ) сервера — он попадёт в ссылку")
  valid_ip "$ENTRY_IP" || { err "Некорректный IP."; exit 1; }

  CLIENT_PORT=$(ask "Клиентский порт (в ссылке). Непопулярный по умолчанию; можно 443" "$CLIENT_PORT_DEF")
  valid_port "$CLIENT_PORT" || { err "Некорректный порт."; exit 1; }
  WG_PORT=$(ask "UDP-порт туннеля AmneziaWG" "$WG_PORT_DEF")
  valid_port "$WG_PORT" || { err "Некорректный порт."; exit 1; }
  DOMAIN=$(ask "FakeTLS-домен (маскировка)" "$DOMAIN_DEF")
  TELEMT_PORT="$TELEMT_PORT_DEF"
  while port_busy "$TELEMT_PORT"; do TELEMT_PORT=$((TELEMT_PORT+1)); done   # внутренний порт telemt — авто-подбор свободного
  [ "$TELEMT_PORT" != "$TELEMT_PORT_DEF" ] && warn "Порт ${TELEMT_PORT_DEF} занят — внутренний порт telemt сдвинут на ${TELEMT_PORT}."

  if port_busy "$WG_PORT"; then err "Порт $WG_PORT уже занят на этом сервере. Выбери другой и перезапусти."; exit 1; fi

  install_awg
  TUN_IF=$(free_awg_iface)
  [ "$TUN_IF" != "awg0" ] && warn "awg0 занят — использую $TUN_IF (существующий туннель не тронут)."

  # ключи: генерим ОБЕ пары здесь (оба сервера твои), приватный A уедет в токене
  mkdir -p "$AWG_DIR"; chmod 700 "$AWG_DIR"
  local B_PRIV B_PUB A_PRIV A_PUB
  B_PRIV=$(awg genkey); B_PUB=$(echo "$B_PRIV" | awg pubkey)
  A_PRIV=$(awg genkey); A_PUB=$(echo "$A_PRIV" | awg pubkey)
  gen_obfs
  SECRET=$(openssl rand -hex 16)

  # конфиг туннеля (B — слушает, A — пир)
  umask 077
  cat > "$AWG_DIR/$TUN_IF.conf" <<EOF
[Interface]
Address = ${TUN_B}/24
ListenPort = ${WG_PORT}
PrivateKey = ${B_PRIV}
Jc = ${OBF_JC}
Jmin = ${OBF_JMIN}
Jmax = ${OBF_JMAX}
S1 = ${OBF_S1}
S2 = ${OBF_S2}
H1 = ${OBF_H1}
H2 = ${OBF_H2}
H3 = ${OBF_H3}
H4 = ${OBF_H4}

[Peer]
PublicKey = ${A_PUB}
AllowedIPs = ${TUN_A}/32
EOF
  systemctl enable --now "awg-quick@$TUN_IF" >/dev/null 2>&1 || { systemctl restart "awg-quick@$TUN_IF"; }
  systemctl is-active --quiet "awg-quick@$TUN_IF" || { err "Туннель $TUN_IF не поднялся."; journalctl -u "awg-quick@$TUN_IF" -n 15 --no-pager; exit 1; }
  ok "Туннель $TUN_IF поднят (B=${TUN_B})."

  # firewall (если ufw есть): открываем оба нужных порта автоматически
  #   - WG-порт туннеля: только с IP входного сервера
  #   - порт telemt: только из туннеля (от tun-IP входного сервера), иначе ufw дропает и прокси недоступен
  if command -v ufw >/dev/null 2>&1; then
    ufw allow from "$ENTRY_IP" to any port "$WG_PORT" proto udp >/dev/null 2>&1 || true
    ufw allow from "$TUN_A" to any port "$TELEMT_PORT" proto tcp >/dev/null 2>&1 || true
    ok "ufw: открыты ${WG_PORT}/udp (с ${ENTRY_IP}) и ${TELEMT_PORT}/tcp (из туннеля)."
  fi

  # telemt: ставим бинарь+сервис (на свободном внутреннем порту), потом перезаписываем конфиг
  say "Ставлю telemt…"
  curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh -s -- -p "$TELEMT_PORT" -d "$DOMAIN" -s "$SECRET" -l en >/dev/null 2>&1 || true
  command -v telemt >/dev/null 2>&1 || { err "telemt не установился. Проверь интернет/доступ к github."; exit 1; }

  # telemt слушает туннельный IP -> должен стартовать ПОСЛЕ туннеля (иначе бинд падает при ребуте).
  # drop-in переживает обновления telemt (основной unit перезапишется, override останется).
  mkdir -p /etc/systemd/system/telemt.service.d
  cat > /etc/systemd/system/telemt.service.d/10-tunnel.conf <<EOF
[Unit]
After=awg-quick@${TUN_IF}.service
Wants=awg-quick@${TUN_IF}.service
StartLimitIntervalSec=0

[Service]
Restart=always
RestartSec=3
EOF
  systemctl daemon-reload

  write_telemt_cfg "$TUN_B" "$TELEMT_PORT" "$ENTRY_IP" "$CLIENT_PORT" "$DOMAIN" "user1=$SECRET"
  systemctl restart telemt
  systemctl is-active --quiet telemt || { err "telemt не запустился."; journalctl -u telemt -n 15 --no-pager; exit 1; }
  ok "telemt слушает ${TUN_B}:${TELEMT_PORT} (proxy_protocol, FakeTLS=${DOMAIN})."

  # сохраняем состояние
  mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
  cat > "$STATE" <<EOF
ROLE=exit
TUN_IF=$TUN_IF
B_IP=$B_IP
ENTRY_IP=$ENTRY_IP
WG_PORT=$WG_PORT
CLIENT_PORT=$CLIENT_PORT
TELEMT_PORT=$TELEMT_PORT
DOMAIN=$DOMAIN
EOF
  chmod 600 "$STATE"

  # токен для входного сервера
  local TOKEN
  TOKEN=$(cat <<EOF | base64 -w0
V=1
BIP=$B_IP
EIP=$ENTRY_IP
WGP=$WG_PORT
CP=$CLIENT_PORT
TP=$TELEMT_PORT
DOM=$DOMAIN
BPUB=$B_PUB
APRIV=$A_PRIV
SEC=$SECRET
JC=$OBF_JC
JMIN=$OBF_JMIN
JMAX=$OBF_JMAX
S1=$OBF_S1
S2=$OBF_S2
H1=$OBF_H1
H2=$OBF_H2
H3=$OBF_H3
H4=$OBF_H4
EOF
)
  echo; hr; ok "ВЫХОДНОЙ сервер готов."; hr
  echo -e "${c_y}1)${c_0} Скопируй ТОКЕН целиком и запусти этот скрипт на ВХОДНОМ (РУ) сервере:"
  echo; echo -e "${c_g}${TOKEN}${c_0}"; echo
  echo -e "${c_y}2)${c_0} Готовая ссылка (заработает после настройки входного сервера):"
  echo -e "   ${c_b}$(mk_link "$ENTRY_IP" "$CLIENT_PORT" "$SECRET" "$DOMAIN")${c_0}"
  echo; warn "Ссылку из инсталлятора telemt (с IP этого сервера) НЕ используй."
}

# ─────────────────────────── РОЛЬ: ВХОД (A) ───────────────────────
setup_entry(){
  hr; say "Настройка ВХОДНОГО сервера (РФ, HAProxy)"; hr
  echo "Вставь ТОКЕН, который напечатал скрипт на выходном сервере, и нажми Enter:"
  local TOKEN; read -r TOKEN
  TOKEN=$(printf '%s' "$TOKEN" | tr -d '[:space:]')   # терминал при переносе строки вставляет пробелы — срезаем
  [ -n "$TOKEN" ] || { err "Пустой токен."; exit 1; }

  local DEC; DEC=$(printf '%s' "$TOKEN" | base64 -d 2>/dev/null) || { err "Токен битый (не base64)."; exit 1; }
  local BIP EIP WGP CP TP DOM BPUB APRIV SEC JC JMIN JMAX S1 S2 H1 H2 H3 H4
  local k v line
  # ВАЖНО: режем только по ПЕРВОМУ '=', иначе хвостовой '=' в base64-ключах теряется
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    k=${line%%=*}; v=${line#*=}
    case "$k" in
      BIP) BIP=$v;; EIP) EIP=$v;; WGP) WGP=$v;; CP) CP=$v;; TP) TP=$v;; DOM) DOM=$v;;
      BPUB) BPUB=$v;; APRIV) APRIV=$v;; SEC) SEC=$v;;
      JC) JC=$v;; JMIN) JMIN=$v;; JMAX) JMAX=$v;; S1) S1=$v;; S2) S2=$v;;
      H1) H1=$v;; H2) H2=$v;; H3) H3=$v;; H4) H4=$v;;
    esac
  done <<< "$DEC"
  valid_ip "${BIP:-}" || { err "В токене нет валидного IP выходного сервера."; exit 1; }
  [ -n "${APRIV:-}" ] && [ -n "${BPUB:-}" ] || { err "В токене нет ключей."; exit 1; }

  install_awg
  local TUN_IF; TUN_IF=$(free_awg_iface)
  [ "$TUN_IF" != "awg0" ] && warn "awg0 занят — использую $TUN_IF."

  mkdir -p "$AWG_DIR"; chmod 700 "$AWG_DIR"; umask 077
  cat > "$AWG_DIR/$TUN_IF.conf" <<EOF
[Interface]
Address = ${TUN_A}/24
PrivateKey = ${APRIV}
Jc = ${JC}
Jmin = ${JMIN}
Jmax = ${JMAX}
S1 = ${S1}
S2 = ${S2}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}

[Peer]
PublicKey = ${BPUB}
Endpoint = ${BIP}:${WGP}
AllowedIPs = ${TUN_B}/32
PersistentKeepalive = 25
EOF
  systemctl enable --now "awg-quick@$TUN_IF" >/dev/null 2>&1 || systemctl restart "awg-quick@$TUN_IF" >/dev/null 2>&1 || true
  if ! awg show "$TUN_IF" >/dev/null 2>&1; then
    err "Туннель $TUN_IF НЕ поднялся (интерфейс не создан)."
    err "Частая причина — битый ключ/параметр в токене. Лог:"
    journalctl -u "awg-quick@$TUN_IF" -n 8 --no-pager 2>/dev/null || true
    exit 1
  fi
  sleep 2
  if ping -c2 -W3 "$TUN_B" >/dev/null 2>&1; then ok "Туннель $TUN_IF поднят, B (${TUN_B}) пингуется."
  else warn "Интерфейс поднят, но пинг до ${TUN_B} не прошёл — проверь firewall ${WGP}/udp на выходном (B)."; fi

  # HAProxy
  command -v haproxy >/dev/null 2>&1 || { say "Ставлю HAProxy…"; export DEBIAN_FRONTEND=noninteractive; apt-get update -qq; apt-get install -y -qq haproxy >/dev/null; }
  cat > "$HAPROXY_CFG" <<EOF
global
    log /dev/log local0
    maxconn 20000

defaults
    log     global
    mode    tcp
    option  dontlognull
    timeout connect 5s
    timeout client  1h
    timeout server  1h

frontend tg_in
    bind *:${CP}
    default_backend telemt_b

backend telemt_b
    server b ${TUN_B}:${TP} check inter 5s rise 2 fall 3 send-proxy-v2
EOF
  haproxy -c -f "$HAPROXY_CFG" >/dev/null 2>&1 || { err "Конфиг HAProxy невалиден."; haproxy -c -f "$HAPROXY_CFG"; exit 1; }
  command -v ufw >/dev/null 2>&1 && ufw allow "${CP}/tcp" >/dev/null 2>&1 || true
  systemctl enable --now haproxy >/dev/null 2>&1 || systemctl restart haproxy
  systemctl restart haproxy
  systemctl is-active --quiet haproxy || { err "HAProxy не запустился."; journalctl -u haproxy -n 15 --no-pager; exit 1; }
  ok "HAProxy слушает *:${CP} → ${TUN_B}:${TP}."

  mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
  cat > "$STATE" <<EOF
ROLE=entry
TUN_IF=$TUN_IF
B_IP=$BIP
ENTRY_IP=$EIP
WG_PORT=$WGP
CLIENT_PORT=$CP
TELEMT_PORT=$TP
DOMAIN=$DOM
DEFAULT_SECRET=$SEC
EOF
  chmod 600 "$STATE"

  echo; hr; ok "ВХОДНОЙ сервер готов. Двойной хоп работает."; hr
  echo -e "Ссылка для Telegram:"
  echo -e "   ${c_b}$(mk_link "$EIP" "$CP" "$SEC" "$DOM")${c_0}"
}

# ─────────────────────────── telemt конфиг ────────────────────────
# write_telemt_cfg <bind_ip> <port> <entry_ip> <client_port> <domain> <user1=secret> [user2=secret ...]
write_telemt_cfg(){
  local bip="$1" port="$2" eip="$3" cp="$4" dom="$5"; shift 5
  { cat <<EOF
[general]
use_middle_proxy = true

[general.modes]
classic = false
secure = false
tls = true

[general.links]
show = "*"
public_host = "${eip}"
public_port = ${cp}

[server]
port = ${port}
proxy_protocol = true

[[server.listeners]]
ip = "${bip}"

[server.api]
enabled = true
listen = "127.0.0.1:9091"
whitelist = ["127.0.0.1/32"]

[censorship]
tls_domain = "${dom}"

[access.users]
EOF
    for u in "$@"; do echo "${u%%=*} = \"${u#*=}\""; done
  } > "$TELEMT_CFG"
  chown root:telemt "$TELEMT_CFG" 2>/dev/null || true
  chmod 640 "$TELEMT_CFG"
}

# ─────────────────────── админка: общие ───────────────────────────
load_state(){ [ -f "$STATE" ] && . "$STATE"; }

show_status(){
  hr; say "Статус / диагностика (роль: ${ROLE})"; hr
  local h
  if awg show "$TUN_IF" >/dev/null 2>&1; then
    h=$(awg show "$TUN_IF" latest-handshakes 2>/dev/null | awk '{print $2}')
    local now age; now=$(date +%s); age=$(( now - ${h:-0} ))
    if [ "${h:-0}" -gt 0 ] && [ "$age" -lt 200 ]; then ok "Туннель: handshake ${age}s назад — ЖИВ"; else warn "Туннель: свежего handshake нет (последний ${age}s назад)"; fi
  else err "Туннель $TUN_IF не найден."; fi

  if [ "$ROLE" = "exit" ]; then
    systemctl is-active --quiet telemt && ok "telemt: запущен" || err "telemt: НЕ запущен"
    local n; n=$(ss -tnH state established "( sport = :$TELEMT_PORT )" 2>/dev/null | wc -l)
    echo "   Активных соединений к telemt: ${n}"
    echo "   IP выхода (что видит Telegram): $(detect_ip || echo '?')"
  else
    systemctl is-active --quiet haproxy && ok "HAProxy: запущен" || err "HAProxy: НЕ запущен"
    local n d
    n=$(ss -tnH state established "( sport = :$CLIENT_PORT )" 2>/dev/null | wc -l)
    d=$(ss -tnH state established "( sport = :$CLIENT_PORT )" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$' | sed 's/:[0-9]*$//' | sort -u | wc -l)
    echo "   Активных клиентских соединений: ${n}  (уникальных устройств ~ ${d})"
  fi
  hr
}

uninstall_all(){
  warn "Полное удаление telemt-double-hop на ЭТОМ сервере."
  [ "$(ask "Точно удалить? напиши yes" "no")" = "yes" ] || { say "Отменено."; return; }
  load_state
  systemctl disable --now "awg-quick@${TUN_IF:-awg0}" >/dev/null 2>&1 || true
  rm -f "$AWG_DIR/${TUN_IF:-awg0}.conf"
  if [ "${ROLE:-}" = "exit" ]; then
    curl -fsSL https://raw.githubusercontent.com/telemt/telemt/main/install.sh | sh -s -- purge >/dev/null 2>&1 || \
      { systemctl disable --now telemt >/dev/null 2>&1 || true; rm -f /etc/systemd/system/telemt.service /bin/telemt; rm -rf /etc/telemt; }
  else
    systemctl disable --now haproxy >/dev/null 2>&1 || true
  fi
  rm -rf "$STATE_DIR"
  systemctl daemon-reload || true
  ok "Удалено. Остальные сервисы (Remnawave/прочие туннели) не тронуты."
}

# ────────────────── админка: только ВЫХОД (B) ─────────────────────
list_users(){ awk '/^\[access.users\]/{f=1;next} /^\[/{f=0} f && /=/{print}' "$TELEMT_CFG"; }

reissue_links(){
  hr; say "Ссылки всех пользователей"; hr
  local line name sec
  while IFS= read -r line; do
    name=$(echo "$line" | sed -E 's/^([^ =]+).*/\1/')
    sec=$(echo "$line"  | sed -E 's/.*"([0-9a-fA-F]{32})".*/\1/')
    [ -n "$name" ] && echo -e "  ${c_y}${name}${c_0}: $(mk_link "$ENTRY_IP" "$CLIENT_PORT" "$sec" "$DOMAIN")"
  done < <(list_users)
  hr
}

add_user(){
  local name sec
  name=$(ask "Имя нового пользователя (латиница/цифры)")
  [[ "$name" =~ ^[a-zA-Z0-9_]+$ ]] || { err "Только латиница, цифры, _"; return; }
  list_users | grep -q "^${name} " && { err "Пользователь '$name' уже есть."; return; }
  sec=$(openssl rand -hex 16)
  cp "$TELEMT_CFG" "$TELEMT_CFG.bak"
  echo "${name} = \"${sec}\"" >> "$TELEMT_CFG"
  if systemctl restart telemt && systemctl is-active --quiet telemt; then
    rm -f "$TELEMT_CFG.bak"; ok "Добавлен '$name'."
    echo -e "  Ссылка: ${c_b}$(mk_link "$ENTRY_IP" "$CLIENT_PORT" "$sec" "$DOMAIN")${c_0}"
  else
    mv "$TELEMT_CFG.bak" "$TELEMT_CFG"; systemctl restart telemt
    err "Ошибка — конфиг откатан, пользователь не добавлен."
  fi
}

del_user(){
  reissue_links
  local name; name=$(ask "Имя пользователя для удаления")
  list_users | grep -q "^${name} " || { err "Нет такого пользователя."; return; }
  [ "$(list_users | wc -l)" -le 1 ] && { err "Это последний пользователь — не удаляю (иначе прокси без доступа)."; return; }
  cp "$TELEMT_CFG" "$TELEMT_CFG.bak"
  sed -i "/^${name} = \"/d" "$TELEMT_CFG"
  if systemctl restart telemt && systemctl is-active --quiet telemt; then
    rm -f "$TELEMT_CFG.bak"; ok "Удалён '$name'."
  else
    mv "$TELEMT_CFG.bak" "$TELEMT_CFG"; systemctl restart telemt; err "Ошибка — откат."
  fi
}

change_domain(){
  local nd; nd=$(ask "Новый FakeTLS-домен (текущий: $DOMAIN)" "$DOMAIN")
  cp "$TELEMT_CFG" "$TELEMT_CFG.bak"
  sed -i -E "s|^tls_domain = .*|tls_domain = \"${nd}\"|" "$TELEMT_CFG"
  if systemctl restart telemt && systemctl is-active --quiet telemt; then
    rm -f "$TELEMT_CFG.bak"; sed -i "s|^DOMAIN=.*|DOMAIN=${nd}|" "$STATE"
    ok "Домен → ${nd}. ВАЖНО: меняется секрет в ссылках — раздай новые (пункт «Показать ссылки»)."
  else
    mv "$TELEMT_CFG.bak" "$TELEMT_CFG"; systemctl restart telemt; err "Ошибка — откат."
  fi
}

change_port_note(){
  warn "Клиентский порт задаётся при установке и хранится на входном сервере (HAProxy)."
  warn "Чтобы сменить порт: на ВХОДНОМ сервере запусти скрипт → «Сменить клиентский порт»."
}

# ────────────────── админка: только ВХОД (A) ──────────────────────
show_entry_link(){
  hr; say "Ссылка (пользователь по умолчанию)"; hr
  echo -e "   ${c_b}$(mk_link "$ENTRY_IP" "$CLIENT_PORT" "$DEFAULT_SECRET" "$DOMAIN")${c_0}"
  warn "Ссылки всех пользователей смотри в админке ВЫХОДНОГО сервера."
  hr
}

change_client_port(){
  local np; np=$(ask "Новый клиентский порт (текущий: $CLIENT_PORT)")
  valid_port "$np" || { err "Некорректный порт."; return; }
  if port_busy "$np"; then err "Порт $np занят."; return; fi
  cp "$HAPROXY_CFG" "$HAPROXY_CFG.bak"
  sed -i -E "s|^    bind \*:.*|    bind *:${np}|" "$HAPROXY_CFG"
  if haproxy -c -f "$HAPROXY_CFG" >/dev/null 2>&1 && systemctl restart haproxy && systemctl is-active --quiet haproxy; then
    rm -f "$HAPROXY_CFG.bak"
    command -v ufw >/dev/null 2>&1 && { ufw allow "${np}/tcp" >/dev/null 2>&1 || true; ufw delete allow "${CLIENT_PORT}/tcp" >/dev/null 2>&1 || true; }
    sed -i "s|^CLIENT_PORT=.*|CLIENT_PORT=${np}|" "$STATE"; CLIENT_PORT=$np
    ok "Порт → ${np}."; show_entry_link
    warn "На ВЫХОДНОМ сервере тоже обнови порт (для корректных ссылок там)."
  else
    mv "$HAPROXY_CFG.bak" "$HAPROXY_CFG"; systemctl restart haproxy; err "Ошибка — откат."
  fi
}

# ─────────────────────────── меню ─────────────────────────────────
admin_menu(){
  load_state
  while true; do
    echo; hr; echo -e "${c_g}telemt double-hop — админка${c_0}  (роль: ${ROLE}, домен: ${DOMAIN}, порт: ${CLIENT_PORT})"; hr
    if [ "$ROLE" = "exit" ]; then
      echo " 1) Показать ссылки всех пользователей"
      echo " 2) Добавить пользователя"
      echo " 3) Удалить пользователя"
      echo " 4) Статус / устройства"
      echo " 5) Сменить FakeTLS-домен"
      echo " 6) Сменить порт (подсказка)"
      echo " 7) Полное удаление"
      echo " 0) Выход"
      case "$(ask "Выбор" "0")" in
        1) reissue_links;; 2) add_user;; 3) del_user;; 4) show_status;;
        5) change_domain;; 6) change_port_note;; 7) uninstall_all; exit 0;; 0) exit 0;;
        *) warn "Нет такого пункта.";;
      esac
    else
      echo " 1) Показать ссылку"
      echo " 2) Статус / устройства"
      echo " 3) Сменить клиентский порт"
      echo " 4) Полное удаление"
      echo " 0) Выход"
      case "$(ask "Выбор" "0")" in
        1) show_entry_link;; 2) show_status;; 3) change_client_port;; 4) uninstall_all; exit 0;; 0) exit 0;;
        *) warn "Нет такого пункта.";;
      esac
    fi
  done
}

# ─────────────────────────── main ─────────────────────────────────
main(){
  need_root; check_os
  if [ -f "$STATE" ]; then admin_menu; exit 0; fi

  hr; echo -e "${c_g}telemt double-hop — установка${c_0}"; hr
  echo "Какой это сервер?"
  echo "  1) ВЫХОДНОЙ (заграница, где telemt ходит к Telegram)  ← начни с него"
  echo "  2) ВХОДНОЙ  (РФ, точка входа клиентов)"
  case "$(ask "Выбор" "1")" in
    1) setup_exit;;
    2) setup_entry;;
    *) err "Неверный выбор."; exit 1;;
  esac
}
main "$@"
