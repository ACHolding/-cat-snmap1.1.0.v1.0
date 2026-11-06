#!/usr/bin/env bash
# cat's nmap — nmapcatsanv0.1.sh
# A port scanner in shell. Connect scans, UDP, banner/version detection,
# host discovery, CIDR and range expansion, nmap-style output.
# No raw sockets, so -sS falls back to connect. bash 3.2+ and perl.
#
#   ./nmapcatsanv0.1.sh 10.0.0.1
#   ./nmapcatsanv0.1.sh -p 22,80,443 -sV 10.0.0.0/24
#   ./nmapcatsanv0.1.sh --top-ports 100 -Pn example.com
#
# A.C Holdings / Team Flames

set -uo pipefail
export LC_ALL=C

VER="0.1"
PROG="cat's nmap"

# ---------------------------------------------------------------- state -----
TARGETS=()
PORTS_SPEC=""
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
DEGREES=0
INTERRUPTED=0

TOP100="7 9 13 21 22 23 25 26 37 53 79 80 81 88 106 110 111 113 119 135 139 143 144 179 199 389 427 443 444 445 465 513 514 515 543 544 548 554 587 631 646 873 990 993 995 1025 1026 1027 1028 1029 1110 1433 1720 1723 1755 1900 2000 2001 2049 2121 2717 3000 3128 3306 3389 3986 4899 5000 5009 5051 5060 5101 5190 5357 5432 5631 5666 5800 5900 6000 6001 6646 7070 8000 8008 8009 8080 8081 8443 8888 9100 9999 10000 32768 49152 49153 49154 49155 49156 49157"

die() { printf '%s: %s\n' "$PROG" "$1" >&2; exit "${2:-1}"; }

usage() {
  cat <<'EOF'
cat's nmap 0.1 — port scanner in shell

Usage: nmapcatsanv0.1.sh [options] <target ...>

Targets   host, 10.0.0.0/24, 10.0.0.1-40, 10.0.0.1-10.0.0.40, comma lists, -iL file

Scan      -sT            TCP connect scan (default)
          -sU            UDP scan
          -sn            ping sweep only, no ports
          -sV            probe open ports for service/version
          -p <spec>      ports: 22,80,1-1024 ; -p- = all 65535
          --top-ports N  scan the N most common ports
          --open         show only open ports

Timing    -T0..-T5       paranoid .. insane (default -T4)
          --max-par N    parallel workers
          --timeout S    connect timeout seconds
          --max-retries N

Output    -oN file        normal text
          -oG file        grepable
          -oX file        XML
          -v              verbose, print state transitions
          --no-degrees    keep percentages in ASCII
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
    -sU) SCAN_UDP=1 ;;
    -sU*) SCAN_UDP=1 ;;
    -sn|-sp) DO_PING=1; SCAN_TCP=0 ;;
    -Pn|-PN) DO_PING=0 ;;
    -sV|-sv) DO_VER=1 ;;
    -p) shift; PORTS_SPEC="${1:-}" ;;
    -p*) PORTS_SPEC="${1#-p}" ;;
    --top-ports) shift; TOP_PORTS="${1:-}" ;;
    --top-ports=*) TOP_PORTS="${1#*=}" ;;
    --open) SHOW_ALL=0 ;;
    -T[0-5]) TIMING="${1#-T}" ;;
    -T) shift; TIMING="${1:-4}" ;;
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
    --no-degrees) DEGREES=1 ;;
    -h|--help) usage; exit 0 ;;
    --version) printf '%s %s\n' "$PROG" "$VER"; exit 0 ;;
    --) shift; while [ $# -gt 0 ]; do TARGETS+=("$1"); shift; done; break ;;
    -*) die "unknown option: $1" 2 ;;
    *) TARGETS+=("$1") ;;
  esac
  shift
done

[ -n "$INFILE" ] && { [ -r "$INFILE" ] || die "cannot read $INFILE" 2; while IFS= read -r l; do
  l="${l%%#*}"; l="$(printf '%s' "$l" | tr -d '[:space:]')"; [ -n "$l" ] && TARGETS+=("$l"); done < "$INFILE"; }

[ "${#TARGETS[@]}" -gt 0 ] || { usage; exit 2; }
[ -n "$PORTS_SPEC$TOP_PORTS" ] || [ "$SCAN_TCP$SCAN_UDP" = "00" ] || { [ "$SCAN_TCP" = 0 ] || PORTS_SPEC="1-1024"; }

case "$TIMING" in
  0) CONN_T=8; MAX_PAR=1 ;; 1) CONN_T=4; MAX_PAR=4 ;;
  2) CONN_T=2; MAX_PAR=16 ;; 3) CONN_T=1; MAX_PAR=32 ;;
  4) CONN_T=1; MAX_PAR=64 ;; 5) CONN_T=1; MAX_PAR=128 ;;
esac
[ "$MAX_PAR" -lt 1 ] && MAX_PAR=1

# ---------------------------------------------------------------- sockets ---
if command -v timeout >/dev/null 2>&1; then
  tcp_state() {
    timeout "$3" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
    case $? in 0) echo open ;; 124|137) echo filtered ;; *) echo closed ;; esac
  }
elif command -v gtimeout >/dev/null 2>&1; then
  tcp_state() {
    gtimeout "$3" bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null
    case $? in 0) echo open ;; 124|137) echo filtered ;; *) echo closed ;; esac
  }
elif command -v perl >/dev/null 2>&1; then
  tcp_state() {
    perl -MIO::Socket::INET -e '
      $SIG{ALRM}=sub{exit 2}; alarm $ARGV[2];
      exit(IO::Socket::INET->new(PeerAddr=>$ARGV[0],PeerPort=>$ARGV[1])?0:1)
    ' "$1" "$2" "$3" 2>/dev/null
    case $? in 0) echo open ;; 2) echo filtered ;; *) echo closed ;; esac
  }
else
  tcp_state() { (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null && echo open || echo closed; }
fi

# grab <ip> <port> <probe> <secs>  -> raw bytes received
grab() {
  perl -MIO::Socket::INET -e '
    my ($a,$p,$t,$pr)=@ARGV;
    $SIG{ALRM}=sub{exit 3}; alarm $t;
    my $s=IO::Socket::INET->new(PeerAddr=>$a,PeerPort=>$p) or exit 1;
    if ($pr ne ""){ $pr =~ s/\\r/\r/g; $pr =~ s/\\n/\n/g; print $s $pr; }
    my $b=""; sysread($s,$b,2048); print $b;
  ' "$1" "$2" "$4" "$3" 2>/dev/null
}

# udp_grab <ip> <port> <probe> <secs>
udp_grab() {
  perl -MIO::Socket::INET -e '
    my ($a,$p,$t,$pr)=@ARGV;
    $SIG{ALRM}=sub{exit 2}; alarm $t;
    my $s=IO::Socket::INET->new(PeerAddr=>$a,PeerPort=>$p,Proto=>"udp") or exit 1;
    print $s $pr; my $b=""; sysread($s,$b,2048); print $b;
  ' "$1" "$2" "$4" "$3" 2>/dev/null
}

# ---------------------------------------------------------------- targets ---
ip2int() { local IFS=.; set -- $1; echo $(( ($1<<24)|($2<<16)|($3<<8)|$4 )); }
int2ip() { echo "$(( ($1>>24)&255 )).$(( ($1>>16)&255 )).$(( ($1>>8)&255 )).$(( $1&255 ))"; }

expand_one() {
  local t="$1" base bits size start i host ips
  case "$t" in
    */*)
      base="${t%/*}"; bits="${t#*/}"
      [ -z "$bits" ] && bits=32
      [ "$bits" -ge 0 ] 2>/dev/null && [ "$bits" -le 32 ] || { echo "bad cidr: $t" >&2; return; }
      start=$(( $(ip2int "$base") & (0xFFFFFFFF ^ ((1<<(32-bits))-1)) ))
      size=$(( 1 << (32-bits) ))
      for ((i=0;i<size;i++)); do int2ip $(( start+i )); done ;;
    *-*-*-*.*)
      local a="${t%%-*}" b="${t##*-}"
      for ((i=$(ip2int "$a");i<=$(ip2int "$b");i++)); do int2ip $i; done ;;
    *-*)
      local pre="${t%.*}" lo="${t##*.}"; lo="${lo%%-*}"; local hi="${t##*-}"
      for ((i=lo;i<=hi;i++)); do echo "$pre.$i"; done ;;
    *)
      if [[ "$t" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "$t"
      else ips=$(getent hosts "$t" 2>/dev/null | awk '{print $1; exit}')
           [ -z "$ips" ] && ips=$(host "$t" 2>/dev/null | awk '/has address/{print $4; exit}')
           [ -z "$ips" ] && ips=$(dig +short A "$t" 2>/dev/null | grep -E '^[0-9.]+$' | head -1)
           if [ -z "$ips" ]; then echo "unresolved: $t" >&2; else echo "$ips"; fi
      fi ;;
  esac
}

# ---------------------------------------------------------------- ports -----
PORTS=()
add_port() { [ "$1" -ge 1 ] 2>/dev/null && [ "$1" -le 65535 ] && PORTS+=("$1"); }

build_ports() {
  local spec="$1" i a b
  [ "$spec" = "-" ] && spec="1-65535"
  for spec in $(printf '%s' "$spec" | tr ',' ' '); do
    case "$spec" in
      *-*) a="${spec%%-*}"; b="${spec##*-}"
           a="${a:-1}"; b="${b:-65535}"
           [ "$a" -le "$b" ] || { local x=$a; a=$b; b=$x; }
           for ((i=a;i<=b;i++)); do add_port $i; done ;;
      *) add_port "$spec" ;;
    esac
  done
}

if [ -n "$TOP_PORTS" ]; then
  n=0
  for p in $TOP100; do PORTS+=("$p"); n=$((n+1)); [ "$n" -ge "$TOP_PORTS" ] && break; done
elif [ -n "$PORTS_SPEC" ]; then
  build_ports "$PORTS_SPEC"
else
  build_ports "1-1024"
fi
[ "${#PORTS[@]}" -gt 0 ] || die "no valid ports" 2

# dedupe + sort ports
PORTS=($(printf '%s\n' "${PORTS[@]}" | sort -n -u))

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
    *) grep -w "$1/tcp" /etc/services 2>/dev/null | awk '{print $1; exit}' | sed 's#/.*##' ;;
  esac
}

# probe for a given port; empty = passive
probe_for() {
  case "$1" in
    80|8080|8000|8888|3000|8081) printf 'HEAD / HTTP/1.0\r\n\r\n' ;;
    443|8443) printf '\x16\x03\x01\x00\x2f\x01\x00\x00\x2b\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x2f\x01\x00' ;;
    25|587) printf 'EHLO cat\r\n' ;;
    110|995) printf 'USER cat\r\n' ;;
    143|993) printf 'a CAPABILITY\r\n' ;;
    21) printf 'SYST\r\n' ;;
    3306) printf '\x00\x00\x00\x01\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' ;;
    6379) printf 'PING\r\n' ;;
    2375) printf 'GET /version HTTP/1.0\r\n\r\n' ;;
    *) printf '' ;;
  esac
}

# version signature match
identify() {
  local ip=$1 port=$2 b
  b=$(grab "$ip" "$port" "$(probe_for "$port")" 3)
  [ -z "$b" ] && { echo ""; return; }
  case "$b" in
    SSH-*) printf 'OpenSSH-ish %s' "$(printf '%s' "$b" | head -1 | cut -c1-40)" ;;
    *'220 '*[Ss][Mm][Tt][Pp]*) printf '%s' "$(printf '%s' "$b" | head -1 | cut -c1-48)" ;;
    *'220 '*FTP*) printf '%s' "$(printf '%s' "$b" | head -1 | cut -c1-48)" ;;
    *Server:*) printf '%s' "$(printf '%s' "$b" | grep -i '^server:' | head -1 | cut -d' ' -f2- | cut -c1-48)" ;;
    *'+OK'*) printf '%s' "$(printf '%s' "$b" | head -1 | cut -c1-40)" ;;
    *'* OK'*) printf 'IMAP %s' "$(printf '%s' "$b" | head -1 | cut -c1-32)" ;;
    *PONG*) printf 'redis' ;;
    $'\x15\x03'*) printf 'tls/ssl' ;;
    *) printf '%s' "$(printf '%s' "$b" | tr -d '\000' | head -1 | cut -c1-40)" ;;
  esac
}

# ---------------------------------------------------------------- results ---
WORK="$(mktemp -d "${TMPDIR:-/tmp}/catnmap.XXXXXX")" || die "mktemp failed"
RES="$WORK/res"; : > "$RES"
HOSTS="$WORK/hosts"; : > "$HOSTS"
trap 'INTERRUPTED=1' INT
trap 'rm -rf "$WORK"' EXIT

emit() { printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$@" >> "$RES"; }
vlog() { [ "$VERBOSE" = 1 ] && printf '%s\n' "$1" >&2; }

# ---------------------------------------------------------------- scanning --
scan_host() {
  local ip="$1" ttl os="" up=1 r
  local rtt_s rtt_e
  if [ "$DO_PING" = 1 ]; then
    r=$(ping -c1 -W1 "$ip" 2>/dev/null || ping -c1 -w1000 "$ip" 2>/dev/null)
    if [ -z "$r" ]; then
      up=0
      # fall back to a probe on a likely port before giving up
      for p in 80 443 22 445; do [ "$(tcp_state "$ip" "$p" "$CONN_T")" = open ] && { up=1; break; }; done
    else
      ttl=$(printf '%s' "$r" | grep -o 'ttl=[0-9]*' | head -1 | cut -d= -f2)
      [ -n "$ttl" ] && { [ "$ttl" -le 64 ] && os="Linux/Unix"; [ "$ttl" -gt 64 ] && [ "$ttl" -le 128 ] && os="Windows"; [ "$ttl" -gt 128 ] && os="Network gear"; }
    fi
  fi
  local name=""
  [ "$RESOLVE" = 1 ] && name=$(getent hosts "$ip" 2>/dev/null | awk '{print $2; exit}')
  [ -z "$name" ] && [ "$RESOLVE" = 1 ] && name=$(host "$ip" 2>/dev/null | awk '/domain name pointer/{print $NF; exit}' | sed 's/\.$//')

  if [ "$up" = 0 ]; then
    printf '%s\tdown\t%s\t%s\n' "$ip" "$name" "$os" >> "$HOSTS"
    vlog "host $ip down"
    return
  fi
  printf '%s\tup\t%s\t%s\n' "$ip" "$name" "$os" >> "$HOSTS"
  [ "$SCAN_TCP" = 0 ] && [ "$SCAN_UDP" = 0 ] && return

  local p st ver svc
  for p in "${PORTS[@]}"; do
    [ "$INTERRUPTED" = 1 ] && return
    if [ "$SCAN_UDP" = 1 ]; then
      local ub
      ub=$(udp_grab "$ip" "$p" "cat" "$CONN_T")
      if [ -n "$ub" ]; then st="open"; else st="open|filtered"; fi
    else
      st=$(tcp_state "$ip" "$p" "$CONN_T")
    fi
    [ "$st" = closed ] && continue
    svc=$(service_of "$p")
    ver=""
    if [ "$DO_VER" = 1 ] && [ "$st" = open ] && [ "$SCAN_UDP" = 0 ]; then
      ver=$(identify "$ip" "$p")
    fi
    emit "$ip" "$p" "${SCAN_UDP:+udp}" "$st" "$svc" "$ver"
    vlog "$ip $p/$([ "$SCAN_UDP" = 1 ] && echo udp || echo tcp) $st"
  done
}

throttle() {
  while [ "$(jobs -rp | wc -l | tr -d ' ')" -ge "$MAX_PAR" ]; do sleep 0.02; done
}

# ---------------------------------------------------------------- main ------
START_TS=$(date '+%Y-%m-%d %H:%M')
{
  echo "Starting $PROG $VER at $START_TS"
  echo
} >&2

ALL_IPS=()
for t in "${TARGETS[@]}"; do
  while IFS= read -r ip; do
    case "$ip" in unresolved*) echo "  $ip" >&2 ;; *) ALL_IPS+=("$ip") ;; esac
  done < <(expand_one "$t")
done
[ "${#ALL_IPS[@]}" -gt 0 ] || die "no targets resolved" 2

printf 'Scanning %d host(s), %d port(s), %d worker(s)\n\n' \
  "${#ALL_IPS[@]}" "${#PORTS[@]}" "$MAX_PAR" >&2

for ip in "${ALL_IPS[@]}"; do
  [ "$INTERRUPTED" = 1 ] && break
  throttle
  scan_host "$ip" &
done
wait

[ "$INTERRUPTED" = 1 ] && echo "interrupted — reporting partial results" >&2

# ---------------------------------------------------------------- render ----
sort -k1,1 -k2,2n "$RES" 2>/dev/null > "$WORK/res.sorted"
sort -k1,1 "$HOSTS" 2>/dev/null > "$WORK/hosts.sorted"

render_host() {
  local ip="$1" name="$2" os="$3" tcp_udp="$4" nopen=0 line p st svc ver total
  total=$(printf '%s\n' "${PORTS[@]}" | wc -l | tr -d ' ')
  if [ -n "$name" ]; then echo "Nmap scan report for $name ($ip)"; else echo "Nmap scan report for $ip"; fi
  if [ "$4" = down ]; then echo "Host is down."; echo; return; fi
  echo "Host is up.${os:+ OS guess: $os}"
  local block
  block=$(awk -F'\t' -v ip="$ip" '$1==ip' "$WORK/res.sorted")
  nopen=$(printf '%s\n' "$block" | grep -c 'open' || true)
  if [ "$SHOW_ALL" = 1 ] && [ -n "$block" ]; then
    local closed=$(( total - nopen ))
    [ "$closed" -gt 0 ] && echo "Not shown: $closed closed/filtered port(s)"
    printf '%-9s %-14s %-14s %s\n' "PORT" "STATE" "SERVICE" "VERSION"
    printf '%s\n' "$block" | while IFS=$'\t' read -r _ p proto st svc ver; do
      printf '%-9s %-14s %-14s %s\n' "$p/$proto" "$st" "$svc" "$ver"
    done
  elif [ "$nopen" -gt 0 ]; then
    printf '%-9s %-14s %-14s %s\n' "PORT" "STATE" "SERVICE" "VERSION"
    printf '%s\n' "$block" | while IFS=$'\t' read -r _ p proto st svc ver; do
      printf '%-9s %-14s %-14s %s\n' "$p/$proto" "$st" "$svc" "$ver"
    done
  fi
  echo
}

OUTPUT="$WORK/out.txt"; : > "$OUTPUT"
{
  echo "Starting $PROG $VER at $START_TS"
  echo
} >> "$OUTPUT"

while IFS=$'\t' read -r ip st name os; do
  [ -z "$ip" ] && continue
  render_host "$ip" "$name" "$os" "$st" >> "$OUTPUT"
done < "$WORK/hosts.sorted"

echo >> "$OUTPUT"
echo "$PROG $VER done at $(date '+%Y-%m-%d %H:%M')" >> "$OUTPUT"

cat "$OUTPUT"

[ -n "$OUT_G" ] && {
  { for ip in "${ALL_IPS[@]}"; do
      printf 'Host: %s ()\t' "$ip"
      awk -F'\t' -v ip="$ip" '$1==ip{printf "%s/%s/%s//%s/// ", $2,$4,$3,$5}' "$WORK/res.sorted"
      echo
    done; } > "$OUT_G"
  echo "grepable output: $OUT_G" >&2
}

[ -n "$OUT_N" ] && { cp "$OUTPUT" "$OUT_N"; echo "normal output: $OUT_N" >&2; }

[ -n "$OUT_X" ] && {
  {
    echo '<?xml version="1.0"?>'
    echo "<nmaprun scanner=\"$PROG\" version=\"$VER\" start=\"$START_TS\">"
    for ip in "${ALL_IPS[@]}"; do
      echo "  <host><address addr=\"$ip\" addrtype=\"ipv4\"/><ports>"
      awk -F'\t' -v ip="$ip" '$1==ip{printf "    <port protocol=\"%s\" portid=\"%s\"><state state=\"%s\"/><service name=\"%s\" version=\"%s\"/></port>\n", $3,$2,$4,$5,$6}' "$WORK/res.sorted"
      echo "  </ports></host>"
    done
    echo '</nmaprun>'
  } > "$OUT_X"
  echo "xml output: $OUT_X" >&2
}

exit 0