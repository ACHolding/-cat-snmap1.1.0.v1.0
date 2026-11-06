#!/usr/bin/env bash
# cat's nmap — cat'snmap1.1.1.sh
# A port scanner in shell. Connect scans, UDP, banner/version detection,
# host discovery, CIDR and range expansion, nmap-style output.
# No raw sockets, so -sS falls back to connect. bash 4.4+ and perl.
#
#   ./catsnmap1.1.1.sh 10.0.0.1
#   ./catsnmap1.1.1.sh -p 22,80,443 -sV 10.0.0.0/24
#   ./catsnmap1.1.1.sh --top-ports 100 -Pn example.com
#
# A.C Holdings / Team Flames

set -uo pipefail
export LC_ALL=C

VER="1.1.1"
PROG="cat's nmap"
SELF="${0##*/}"

if [ "${BASH_VERSINFO[0]:-0}" -lt 4 ] ||
   { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]:-0}" -lt 4 ]; }; then
  printf '%s: bash 4.4 or newer required\n' "$PROG" >&2
  exit 2
fi

# ---------------------------------------------------------------- state -----
TARGETS=()
PORTS=()
PORTS_SPEC=""
PORTS_GIVEN=0
SCAN_TCP=1
SCAN_UDP=0
DO_VER=0
DO_PING=1
RESOLVE=1
SHOW_ALL=1
VERBOSE=0
TIMING=4
TOP_PORTS=""
MAX_PAR=64
CONN_T=1
MAX_RETRY=2
OUT_N=""
OUT_G=""
OUT_X=""
INFILE=""
NO_DEGREES=0
INTERRUPTED=0

TOP100="7 9 13 21 22 23 25 26 37 53 79 80 81 88 106 110 111 113 119 135 139 143 144 179 199 389 427 443 444 445 465 513 514 515 543 544 548 554 587 631 646 873 990 993 995 1025 1026 1027 1028 1029 1110 1433 1720 1723 1755 1900 2000 2001 2049 2121 2717 3000 3128 3306 3389 3986 4899 5000 5009 5051 5060 5101 5190 5357 5432 5631 5666 5800 5900 6000 6001 6646 7070 8000 8008 8009 8080 8081 8443 8888 9100 9999 10000 32768 49152 49153 49154 49155 49156 49157"

die()  { printf '%s: %s\n' "$PROG" "$1" >&2; exit "${2:-1}"; }
warn() { printf '%s: %s\n' "$PROG" "$1" >&2; }
is_num() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

usage() {
  cat <<EOF
$PROG $VER — port scanner in shell

Usage: $SELF [options] <target ...>

Targets   host, 10.0.0.0/24, 10.0.0.1-40, 10.0.0.1-10.0.0.40, comma lists, -iL file

Scan      -sT            TCP connect scan (default)
          -sU            UDP scan
          -sn            ping sweep only, no ports
          -sV            probe open ports for service/version (needs perl)
          -p <spec>      ports: 22,80,1-1024 ; -p- = all 65535
          --top-ports N  scan the N most common ports (1-100)
          --open         show only open ports

Timing    -T0..-T5       paranoid .. insane (default -T4)
          --max-par N    parallel workers
          --timeout S    connect timeout seconds
          --max-retries N  retries on a filtered port (default 2)

Output    -oN file        normal text
          -oG file        grepable
          -oX file        XML
          -v              verbose, print state transitions
          --no-degrees    plain counts in the summary, no percentages
          -n              no reverse DNS
          -Pn             skip host discovery, treat all as up

Ctrl-C prints results gathered so far.
EOF
}

# ---------------------------------------------------------------- args ------
while [ $# -gt 0 ]; do
  case "$1" in
    -sT) SCAN_TCP=1; SCAN_UDP=0 ;;
    -sS|-sA|-sF|-sN) SCAN_TCP=1; SCAN_UDP=0 ;;
    -sU) SCAN_UDP=1; SCAN_TCP=0 ;;
    -sn|-sp) DO_PING=1; SCAN_TCP=0; SCAN_UDP=0 ;;
    -Pn|-PN) DO_PING=0 ;;
    -sV|-sv) DO_VER=1 ;;
    -p) shift; [ $# -gt 0 ] || die "option -p needs a port spec" 2
        PORTS_SPEC="$1"; PORTS_GIVEN=1 ;;
    -p*) PORTS_SPEC="${1#-p}"; PORTS_GIVEN=1 ;;
    --top-ports) shift; [ $# -gt 0 ] || die "option --top-ports needs a number" 2
                 TOP_PORTS="$1" ;;
    --top-ports=*) TOP_PORTS="${1#*=}" ;;
    --open) SHOW_ALL=0 ;;
    -T[0-5]) TIMING="${1#-T}" ;;
    -T) shift; [ $# -gt 0 ] || die "option -T needs a level" 2; TIMING="$1" ;;
    --max-par) shift; MAX_PAR="${1:-64}" ;;
    --timeout) shift; CONN_T="${1:-1}" ;;
    --max-retries) shift; MAX_RETRY="${1:-2}" ;;
    -oN) shift; OUT_N="${1:-}" ;;
    -oG) shift; OUT_G="${1:-}" ;;
    -oX) shift; OUT_X="${1:-}" ;;
    -iL) shift; INFILE="${1:-}" ;;
    -n) RESOLVE=0 ;;
    -R) RESOLVE=1 ;;
    -v|-vv) VERBOSE=1 ;;
    --no-degrees) NO_DEGREES=1 ;;
    -h|--help) usage; exit 0 ;;
    --version) printf '%s %s\n' "$PROG" "$VER"; exit 0 ;;
    --) shift; while [ $# -gt 0 ]; do TARGETS+=("$1"); shift; done; continue ;;
    -*) die "unknown option: $1" 2 ;;
    *) TARGETS+=("$1") ;;
  esac
  shift
done

if [ -n "$INFILE" ]; then
  [ -r "$INFILE" ] || die "cannot read $INFILE" 2
  while IFS= read -r l; do
    l="${l%%#*}"
    l="$(printf '%s' "$l" | tr -d '[:space:]')"
    [ -n "$l" ] && TARGETS+=("$l")
  done < "$INFILE"
fi

[ "${#TARGETS[@]}" -gt 0 ] || { usage; exit 2; }

case "$TIMING" in
  0) CONN_T=8; MAX_PAR=1 ;;
  1) CONN_T=4; MAX_PAR=4 ;;
  2) CONN_T=2; MAX_PAR=16 ;;
  3) CONN_T=1; MAX_PAR=32 ;;
  4) CONN_T=1; MAX_PAR=64 ;;
  5) CONN_T=1; MAX_PAR=128 ;;
  *) TIMING=4; CONN_T=1; MAX_PAR=64 ;;
esac

is_num "$MAX_PAR" || MAX_PAR=64
is_num "$CONN_T" || CONN_T=1
is_num "$MAX_RETRY" || MAX_RETRY=2
[ "$MAX_PAR" -lt 1 ] && MAX_PAR=1
[ "$CONN_T" -lt 1 ] && CONN_T=1

# ---------------------------------------------------------------- sockets ---
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_BIN=timeout
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_BIN=gtimeout
else
  TIMEOUT_BIN=""
fi

HAVE_PERL=0
command -v perl >/dev/null 2>&1 && HAVE_PERL=1

# tcp_state_once -> open | closed | filtered
if [ -n "$TIMEOUT_BIN" ]; then
  tcp_state_once() {
    "$TIMEOUT_BIN" "$3" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
    case $? in 0) echo open ;; 124|137) echo filtered ;; *) echo closed ;; esac
  }
elif [ "$HAVE_PERL" = 1 ]; then
  tcp_state_once() {
    perl -MIO::Socket::INET -e '
      $SIG{ALRM}=sub{exit 2}; alarm $ARGV[2];
      exit(IO::Socket::INET->new(PeerAddr=>$ARGV[0],PeerPort=>$ARGV[1])?0:1)
    ' "$1" "$2" "$3" 2>/dev/null
    case $? in 0) echo open ;; 2) echo filtered ;; *) echo closed ;;
  }
else
  warn "no timeout(1) or perl: connect timeouts are not enforced"
  tcp_state_once() { (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null && echo open || echo closed; }
fi

# tcp_state -> retries a filtered result up to MAX_RETRY times
tcp_state() {
  local st i=0
  while :; do
    st=$(tcp_state_once "$1" "$2" "$3")
    [ "$st" = filtered ] || break
    i=$((i+1))
    [ "$i" -gt "$MAX_RETRY" ] && break
  done
  printf '%s' "$st"
}

# grab <ip> <port> <hexprobe> <secs> -> raw bytes received
grab() {
  perl -MIO::Socket::INET -e '
    my ($a,$p,$t,$pr)=@ARGV;
    $SIG{ALRM}=sub{exit 3}; alarm $t;
    my $s=IO::Socket::INET->new(PeerAddr=>$a,PeerPort=>$p) or exit 1;
    print $s pack("H*", $pr) if $pr ne "";
    my $b="";
    for (1..2) { my $n=sysread($s,$b,2048,length $b); last unless $n; }
    print $b;
  ' "$1" "$2" "$4" "$3" 2>/dev/null
}

# udp_grab <ip> <port> <hexprobe> <secs>
udp_grab() {
  perl -MIO::Socket::INET -e '
    my ($a,$p,$t,$pr)=@ARGV;
    $SIG{ALRM}=sub{exit 2}; alarm $t;
    my $s=IO::Socket::INET->new(PeerAddr=>$a,PeerPort=>$p,Proto=>"udp") or exit 1;
    print $s pack("H*", $pr);
    my $b=""; sysread($s,$b,2048); print $b;
  ' "$1" "$2" "$4" "$3" 2>/dev/null
}

# ---------------------------------------------------------------- targets ---
ip2int() {
  local IFS=.
  set -- $1
  printf '%s' $(( ((10#${1:-0})<<24) | ((10#${2:-0})<<16) | ((10#${3:-0})<<8) | (10#${4:-0}) ))
}
int2ip() { printf '%s.%s.%s.%s' "$(( ($1>>24)&255 ))" "$(( ($1>>16)&255 ))" "$(( ($1>>8)&255 ))" "$(( $1&255 ))"; }

is_ipv4() { case "$1" in ''|*[!0-9.]*) return 1 ;; esac; [[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; }

expand_one() {
  local t="$1" base bits size start i pre lo hi a b ips
  case "$t" in
    */*)
      base="${t%/*}"; bits="${t#*/}"
      [ -z "$bits" ] && bits=32
      if ! is_num "$bits" || [ "$bits" -gt 32 ]; then warn "bad cidr: $t"; return 0; fi
      is_ipv4 "$base" || { warn "bad cidr base: $t"; return 0; }
      start=$(( $(ip2int "$base") & (0xFFFFFFFF ^ ((1<<(32-bits))-1)) ))
      size=$(( 1 << (32-bits) ))
      for ((i=0;i<size;i++)); do int2ip $(( start+i )); done ;;
    *.*.*.*-*.*.*.*)
      a="${t%%-*}"; b="${t##*-}"
      is_ipv4 "$a" && is_ipv4 "$b" || { warn "bad range: $t"; return 0; }
      for ((i=$(ip2int "$a");i<=$(ip2int "$b");i++)); do int2ip "$i"; done ;;
    *.*-*)
      pre="${t%.*}"; lo="${t##*.}"; lo="${lo%%-*}"; hi="${t##*-}"
      is_ipv4 "$pre" && is_num "$lo" && is_num "$hi" || { warn "bad range: $t"; return 0; }
      for ((i=lo;i<=hi;i++)); do printf '%s.%s\n' "$pre" "$i"; done ;;
    *)
      if is_ipv4 "$t"; then
        printf '%s\n' "$t"
      else
        ips=$(getent hosts "$t" 2>/dev/null | awk '{print $1; exit}')
        [ -z "$ips" ] && ips=$(host "$t" 2>/dev/null | awk '/has address/{print $4; exit}')
        [ -z "$ips" ] && ips=$(dig +short A "$t" 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
        if [ -z "$ips" ]; then warn "unresolved: $t"; else printf '%s\n' "$ips"; fi
      fi ;;
  esac
}

# ---------------------------------------------------------------- ports -----
add_port() {
  is_num "$1" || return 0
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ] || return 0
  PORTS+=("$1")
}

build_ports() {
  local spec="$1" tok a b i t
  [ "$spec" = "-" ] && spec="1-65535"
  for tok in $(printf '%s' "$spec" | tr ',' ' '); do
    case "$tok" in
      *-*)
        a="${tok%%-*}"; b="${tok##*-}"
        a="${a:-1}"; b="${b:-65535}"
        if ! is_num "$a" || ! is_num "$b"; then warn "bad port range: $tok"; continue; fi
        [ "$a" -le "$b" ] || { t=$a; a=$b; b=$t; }
        [ "$a" -ge 1 ] || a=1
        [ "$b" -le 65535 ] || b=65535
        for ((i=a;i<=b;i++)); do add_port "$i"; done ;;
      *) if is_num "$tok"; then add_port "$tok"; else warn "bad port: $tok"; fi ;;
    esac
  done
}

if [ -n "$TOP_PORTS" ]; then
  is_num "$TOP_PORTS" || die "--top-ports needs a number" 2
  [ "$TOP_PORTS" -ge 1 ] || TOP_PORTS=1
  [ "$TOP_PORTS" -le 100 ] || TOP_PORTS=100
  n=0
  for p in $TOP100; do PORTS+=("$p"); n=$((n+1)); [ "$n" -ge "$TOP_PORTS" ] && break; done
elif [ "$PORTS_GIVEN" = 1 ]; then
  [ -n "$PORTS_SPEC" ] || die "-p needs a port spec" 2
  build_ports "$PORTS_SPEC"
elif [ "$SCAN_TCP" = 1 ] || [ "$SCAN_UDP" = 1 ]; then
  build_ports "1-1024"
fi

[ "${#PORTS[@]}" -gt 0 ] && PORTS=($(printf '%s\n' "${PORTS[@]}" | sort -n -u))
NPORTS=${#PORTS[@]}

if { [ "$SCAN_TCP" = 1 ] || [ "$SCAN_UDP" = 1 ]; } && [ "$NPORTS" -eq 0 ]; then
  die "no valid ports to scan" 2
fi

if [ "$DO_VER" = 1 ] && [ "$HAVE_PERL" = 0 ]; then
  warn "perl not found: -sV disabled"
  DO_VER=0
fi
if [ "$SCAN_UDP" = 1 ] && [ "$HAVE_PERL" = 0 ]; then
  warn "perl not found: UDP scanning is unreliable without it"
fi

# ---------------------------------------------------------------- services --
service_of() {
  case "$1" in
    21) echo ftp ;; 22) echo ssh ;; 23) echo telnet ;; 25) echo smtp ;;
    53) echo domain ;; 80|8000|8080|8888) echo http ;; 110) echo pop3 ;;
    111) echo rpcbind ;; 135) echo msrpc ;; 139) echo netbios-ssn ;;
    143) echo imap ;; 161) echo snmp ;; 389) echo ldap ;; 443|8443) echo https ;;
    445) echo microsoft-ds ;; 465) echo smtps ;; 512) echo exec ;;
    513) echo login ;; 514) echo shell ;; 587) echo submission ;;
    631) echo ipp ;; 993) echo imaps ;; 995) echo pop3s ;; 1433) echo ms-sql-s ;;
    1521) echo oracle ;; 2049) echo nfs ;; 2375) echo docker ;;
    3000) echo http ;; 3306) echo mysql ;; 3389) echo ms-wbt-server ;;
    5000) echo upnp ;; 5432) echo postgresql ;; 5900) echo vnc ;;
    5985|5986) echo wsman ;; 6379) echo redis ;; 8081) echo http ;;
    9200) echo elasticsearch ;; 27017) echo mongod ;;
    *) grep -w "$1/${2:-tcp}" /etc/services 2>/dev/null | awk '{print $1; exit}' | sed 's#/.*##' ;;
  esac
}

# probe for a given port, as hex (bash vars cannot hold NUL, so hex it is)
probe_for() {
  case "$1" in
    80|8080|8000|8888|3000|8081) printf '48454144202f20485454502f312e300d0a0d0a' ;;
    443|8443) printf '160301002d01000029030300000000000000000000000000000000000000000000000000000002002f0100' ;;
    25|587) printf '45484c4f206361740d0a' ;;
    110|995) printf '55534552206361740d0a' ;;
    143|993) printf '61204341504142494c4954590d0a' ;;
    21) printf '535953540d0a' ;;
    3306) printf '010000000a' ;;
    6379) printf '50494e470d0a' ;;
    2375) printf '474554202f76657273696f6e20485454502f312e300d0a0d0a' ;;
    *) printf '' ;;
  esac
}

# strip control chars/tabs so a banner cannot break the TSV output
clean() { printf '%s' "$1" | tr -d '\000\r\n' | tr '\t' ' ' | cut -c1-64; }

identify() {
  local ip=$1 port=$2 b first srv
  b=$(grab "$ip" "$port" "$(probe_for "$port")" 3)
  [ -z "$b" ] && return 0
  first=$(printf '%s\n' "$b" | head -1)
  case "$b" in
    $'\x16\x03'*)              printf 'tls/ssl' ;;
    SSH-*)                     printf 'ssh %s' "$(clean "$first")" ;;
    *'220 '*[Ss][Mm][Tt][Pp]*) printf 'smtp %s' "$(clean "$first")" ;;
    *'220 '*[Ff][Tt][Pp]*)     printf 'ftp %s' "$(clean "$first")" ;;
    *Server:*)
      srv=$(printf '%s\n' "$b" | grep -i '^server:' | head -1 | cut -d' ' -f2-)
      clean "$srv" ;;
    *'+OK'*)                   printf 'pop3 %s' "$(clean "$first")" ;;
    *'* OK'*)                  printf 'imap %s' "$(clean "$first")" ;;
    *PONG*)                    printf 'redis' ;;
    *)                         clean "$first" ;;
  esac
}

# ---------------------------------------------------------------- results ---
WORK="$(mktemp -d "${TMPDIR:-/tmp}/catnmap.XXXXXX")" || die "mktemp failed"
RES="$WORK/res"; : > "$RES"
HOSTS="$WORK/hosts"; : > "$HOSTS"
exec 8>>"$HOSTS"
exec 9>>"$RES"

HAS_FLOCK=0
command -v flock >/dev/null 2>&1 && HAS_FLOCK=1

lock()   { [ "$HAS_FLOCK" = 1 ] && flock -x "$1"; }
unlock() { [ "$HAS_FLOCK" = 1 ] && flock -u "$1"; }

trap 'INTERRUPTED=1; kill $(jobs -p) 2>/dev/null' INT
trap 'rm -rf "$WORK"' EXIT

emit() {
  lock 9
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >&9
  unlock 9
}
emit_host() {
  lock 8
  printf '%s\t%s\t%s\t%s\n' "$@" >&8
  unlock 8
}
vlog() { [ "$VERBOSE" = 1 ] && printf '%s\n' "$1" >&2; return 0; }
xml_esc() { printf '%s' "$1" | tr -d '\000\r\n' | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'; }

# ---------------------------------------------------------------- scanning --
ping_once() {
  ping -c1 -W1 "$1" 2>/dev/null && return 0
  if [ -n "$TIMEOUT_BIN" ]; then
    "$TIMEOUT_BIN" 3 ping -c1 "$1" 2>/dev/null
  else
    ping -c1 "$1" 2>/dev/null
  fi
}

scan_host() {
  local ip="$1" ttl os="" up=1 r proto p st ver svc ub name=""
  if [ "$DO_PING" = 1 ]; then
    r=$(ping_once "$ip")
    if [ -z "$r" ]; then
      up=0
      for p in 80 443 22 445; do
        [ "$(tcp_state "$ip" "$p" "$CONN_T")" = open ] && { up=1; break; }
      done
    else
      ttl=$(printf '%s' "$r" | grep -oiE 'ttl=[0-9]+' | head -1 | cut -d= -f2)
      if [ -n "$ttl" ]; then
        [ "$ttl" -le 64 ] && os="Linux/Unix"
        [ "$ttl" -gt 64 ] && [ "$ttl" -le 128 ] && os="Windows"
        [ "$ttl" -gt 128 ] && os="Network gear"
      fi
    fi
  fi

  if [ "$RESOLVE" = 1 ]; then
    name=$(getent hosts "$ip" 2>/dev/null | awk '{print $2; exit}')
    [ -z "$name" ] && name=$(host "$ip" 2>/dev/null | awk '/domain name pointer/{print $NF; exit}' | sed 's/\.$//')
  fi

  if [ "$up" = 0 ]; then
    emit_host "$ip" down "$name" "$os"
    vlog "host $ip down"
    return 0
  fi
  emit_host "$ip" up "$name" "$os"
  [ "$SCAN_TCP" = 0 ] && [ "$SCAN_UDP" = 0 ] && return 0

  if [ "$SCAN_UDP" = 1 ]; then proto=udp; else proto=tcp; fi
  for p in "${PORTS[@]}"; do
    [ "$INTERRUPTED" = 1 ] && return 0
    if [ "$SCAN_UDP" = 1 ]; then
      ub=$(udp_grab "$ip" "$p" "$(probe_for "$p")" "$CONN_T")
      if [ -n "$ub" ]; then st="open"; else st="open|filtered"; fi
    else
      st=$(tcp_state "$ip" "$p" "$CONN_T")
    fi
    [ "$st" = closed ] && continue
    svc=$(service_of "$p" "$proto")
    ver=""
    if [ "$DO_VER" = 1 ] && [ "$st" = open ] && [ "$proto" = tcp ]; then
      ver=$(identify "$ip" "$p")
    fi
    emit "$ip" "$p" "$proto" "$st" "$svc" "$ver"
    vlog "$ip $p/$proto $st"
  done
}

throttle() {
  while [ "$(jobs -rp | wc -l | tr -d ' ')" -ge "$MAX_PAR" ]; do sleep 0.02; done
}

pct() {
  [ "$2" -le 0 ] && { printf '0'; return 0; }
  local v=$(( $1 * 100 / $2 ))
  if [ "$NO_DEGREES" = 1 ]; then printf '%s' "$v"; else printf '%s%%' "$v"; fi
}

# ---------------------------------------------------------------- main ------
START_TS=$(date '+%Y-%m-%d %H:%M')
printf 'Starting %s %s at %s\n\n' "$PROG" "$VER" "$START_TS" >&2

ALL_IPS=()
for t in "${TARGETS[@]}"; do
  while IFS= read -r ip; do
    [ -n "$ip" ] && ALL_IPS+=("$ip")
  done < <(expand_one "$t")
done
[ "${#ALL_IPS[@]}" -gt 0 ] || die "no targets resolved" 2
[ "${#ALL_IPS[@]}" -gt 1 ] && ALL_IPS=($(printf '%s\n' "${ALL_IPS[@]}" | awk '!seen[$0]++'))

printf 'Scanning %d host(s), %d port(s), %d worker(s)\n\n' \
  "${#ALL_IPS[@]}" "$NPORTS" "$MAX_PAR" >&2

for ip in "${ALL_IPS[@]}"; do
  [ "$INTERRUPTED" = 1 ] && break
  throttle
  scan_host "$ip" &
done
wait

[ "$INTERRUPTED" = 1 ] && printf 'interrupted — reporting partial results\n' >&2

# ---------------------------------------------------------------- render ----
sort -k1,1 -k2,2n "$RES" > "$WORK/res.sorted" 2>/dev/null
sort -k1,1 "$HOSTS" > "$WORK/hosts.sorted" 2>/dev/null

render_host() {
  local ip="$1" name="$2" os="$3" state="$4" block nopen=0 closed
  if [ -n "$name" ]; then echo "Nmap scan report for $name ($ip)"; else echo "Nmap scan report for $ip"; fi
  if [ "$state" = down ]; then echo "Host is down."; echo; return 0; fi
  if [ -n "$os" ]; then echo "Host is up. OS guess: $os"; else echo "Host is up."; fi

  block=$(awk -F'\t' -v ip="$ip" '$1==ip' "$WORK/res.sorted")
  [ -n "$block" ] && nopen=$(printf '%s\n' "$block" | awk -F'\t' '$4 ~ /^open/{n++} END{print n+0}')

  if [ "$NPORTS" -gt 0 ] && [ "$SHOW_ALL" = 1 ]; then
    closed=$(( NPORTS - nopen ))
    [ "$closed" -gt 0 ] && echo "Not shown: $closed closed/filtered port(s) ($(pct "$closed" "$NPORTS"))"
  fi

  if [ -n "$block" ] && { [ "$SHOW_ALL" = 1 ] || [ "$nopen" -gt 0 ]; }; then
    printf '%-9s %-14s %-14s %s\n' "PORT" "STATE" "SERVICE" "VERSION"
    printf '%s\n' "$block" | while IFS=$'\t' read -r _ p proto st svc ver; do
      printf '%-9s %-14s %-14s %s\n' "$p/$proto" "$st" "$svc" "$ver"
    done
  fi
  echo
}

OUTPUT="$WORK/out.txt"; : > "$OUTPUT"
printf 'Starting %s %s at %s\n\n' "$PROG" "$VER" "$START_TS" >> "$OUTPUT"

while IFS=$'\t' read -r ip state name os; do
  [ -z "$ip" ] && continue
  render_host "$ip" "$name" "$os" "$state" >> "$OUTPUT"
done < "$WORK/hosts.sorted"

printf '\n%s %s done at %s\n' "$PROG" "$VER" "$(date '+%Y-%m-%d %H:%M')" >> "$OUTPUT"

cat "$OUTPUT"

if [ -n "$OUT_G" ]; then
  {
    for ip in "${ALL_IPS[@]}"; do
      hn=$(awk -F'\t' -v ip="$ip" '$1==ip{print $3; exit}' "$WORK/hosts.sorted")
      printf 'Host: %s (%s)\t' "$ip" "$hn"
      awk -F'\t' -v ip="$ip" '$1==ip{printf "%s/%s/%s//%s/// ", $2,$4,$3,$5}' "$WORK/res.sorted"
      echo
    done
  } > "$OUT_G"
  printf 'grepable output: %s\n' "$OUT_G" >&2
fi

[ -n "$OUT_N" ] && { cp "$OUTPUT" "$OUT_N"; printf 'normal output: %s\n' "$OUT_N" >&2; }

if [ -n "$OUT_X" ]; then
  {
    printf '<?xml version="1.0"?>\n'
    printf '<nmaprun scanner="%s" version="%s" startstr="%s">\n' \
      "$(xml_esc "$PROG")" "$VER" "$(xml_esc "$START_TS")"
    for ip in "${ALL_IPS[@]}"; do
      hstate=$(awk -F'\t' -v ip="$ip" '$1==ip{print $2; exit}' "$WORK/hosts.sorted")
      hn=$(awk -F'\t' -v ip="$ip" '$1==ip{print $3; exit}' "$WORK/hosts.sorted")
      printf '  <host><status state="%s"/><address addr="%s" addrtype="ipv4"/>' "$hstate" "$ip"
      [ -n "$hn" ] && printf '<hostnames><hostname name="%s"/></hostnames>' "$(xml_esc "$hn")"
      printf '<ports>\n'
      while IFS=$'\t' read -r _ p proto pstate svc ver; do
        [ -z "$p" ] && continue
        printf '    <port protocol="%s" portid="%s"><state state="%s"/><service name="%s" version="%s"/></port>\n' \
          "$proto" "$p" "$pstate" "$(xml_esc "$svc")" "$(xml_esc "$ver")"
      done <<< "$(awk -F'\t' -v ip="$ip" '$1==ip' "$WORK/res.sorted")"
      printf '  </ports></host>\n'
    done
    printf '</nmaprun>\n'
  } > "$OUT_X"
  printf 'xml output: %s\n' "$OUT_X" >&2
fi

exit 0
