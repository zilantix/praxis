#!/usr/bin/env bash
set -euo pipefail

SESSION_ID="${1:?session_id required}"
CONFIG_ID="${2:?config_id required}"
MUX_MODE="${3:?mux mode required}"
RESOLUTION_MODE="${4:?resolution mode required}"

source /opt/praxis/configs/lab_ips_cycle2.env

TARGET_HOST="praxis-destination.praxis"
URL="https://${TARGET_HOST}:${DEST_HTTPS_PORT}/"

PCAP="/opt/praxis/pcaps/${SESSION_ID}.pcap"
DNS_PCAP="/opt/praxis/pcaps/${SESSION_ID}_dns.pcap"
CURL_OUT="/opt/praxis/logs/${SESSION_ID}_curl.out"
CURL_LOG="/opt/praxis/logs/${SESSION_ID}_curl.log"
TCPDUMP_LOG="/opt/praxis/logs/${SESSION_ID}_tcpdump.log"
DNS_TCPDUMP_LOG="/opt/praxis/logs/${SESSION_ID}_dns_tcpdump.log"
CATALOG="/opt/praxis/solution/sweep/phase21_rq3_curl_catalog.csv"

mkdir -p /opt/praxis/pcaps /opt/praxis/logs /opt/praxis/solution/sweep

if [ ! -f "$CATALOG" ]; then
  echo "session_id,config_id,mux_mode,resolution_mode,url,pcap_file,dns_pcap_file,curl_log,success,http_code,remote_ip,started_utc,completed_utc" > "$CATALOG"
fi

remove_dns_block() {
  sudo iptables -D OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null || true
  sudo iptables -D OUTPUT -p tcp --dport 53 -j REJECT 2>/dev/null || true
}

remove_host_mapping() {
  sudo sed -i "/[[:space:]]${TARGET_HOST}/d" /etc/hosts 2>/dev/null || true
}

cleanup() {
  remove_dns_block
  remove_host_mapping
  if command -v resolvectl >/dev/null 2>&1; then
    sudo resolvectl flush-caches 2>/dev/null || true
  fi
}
trap cleanup EXIT

block_dns() {
  if ! command -v iptables >/dev/null 2>&1; then
    echo "ERROR: iptables is required for DNS blocking but is not installed."
    exit 1
  fi

  remove_dns_block
  sudo iptables -I OUTPUT 1 -p udp --dport 53 -j REJECT
  sudo iptables -I OUTPUT 1 -p tcp --dport 53 -j REJECT
}

STARTED_UTC="$(date -u +%FT%TZ)"

echo "=== Phase 21 RQ3 curl session ==="
echo "session_id=$SESSION_ID"
echo "config_id=$CONFIG_ID"
echo "mux_mode=$MUX_MODE"
echo "resolution_mode=$RESOLUTION_MODE"
echo "url=$URL"
echo "started_utc=$STARTED_UTC"
echo

cleanup

echo "=== Starting Xray client ==="
/opt/praxis/bin/start_xray_client.sh "$MUX_MODE"

echo
echo "=== Starting tcpdump ==="
sudo tcpdump -i any -nn -s 0 \
  "host ${PROXY_IP} and port ${PROXY_PORT}" \
  -w "$PCAP" > "$TCPDUMP_LOG" 2>&1 &
TCPDUMP_PID=$!

sudo tcpdump -i any -nn -s 0 \
  "host ${DNS_IP} and port 53" \
  -w "$DNS_PCAP" > "$DNS_TCPDUMP_LOG" 2>&1 &
DNS_TCPDUMP_PID=$!

sleep 2

HTTP_CODE="000"
REMOTE_IP="NA"
SUCCESS="0"

echo
echo "=== Applying resolution mode ==="

case "$RESOLUTION_MODE" in
  standard_dns_lab)
    echo "Querying lab DNS ${DNS_IP} for ${TARGET_HOST}"
    RESOLVED_IP="$(dig +short +time=2 +tries=1 @"$DNS_IP" "$TARGET_HOST" A | tail -1)"
    echo "resolved_ip=$RESOLVED_IP"

    if [ -n "$RESOLVED_IP" ]; then
      set +e
      curl -k -sS \
        --socks5 127.0.0.1:${CLIENT_SOCKS_PORT} \
        --resolve "${TARGET_HOST}:${DEST_HTTPS_PORT}:${RESOLVED_IP}" \
        "$URL" \
        -o "$CURL_OUT" \
        -w 'http_code=%{http_code} remote_ip=%{remote_ip} total_time=%{time_total}\n' \
        > "$CURL_LOG" 2>&1
      RC=$?
      set -e
    else
      echo "DNS resolution failed" > "$CURL_LOG"
      RC=1
    fi
    ;;

  dns_blocked)
    block_dns
    sudo resolvectl flush-caches 2>/dev/null || true

    set +e
    curl -k -sS \
      --socks5 127.0.0.1:${CLIENT_SOCKS_PORT} \
      "$URL" \
      -o "$CURL_OUT" \
      -w 'http_code=%{http_code} remote_ip=%{remote_ip} total_time=%{time_total}\n' \
      > "$CURL_LOG" 2>&1
    RC=$?
    set -e
    ;;

  decentralized_resolution)
    echo "${DEST_IP} ${TARGET_HOST}" | sudo tee -a /etc/hosts >/dev/null
    block_dns

    set +e
    curl -k -sS \
      --socks5 127.0.0.1:${CLIENT_SOCKS_PORT} \
      "$URL" \
      -o "$CURL_OUT" \
      -w 'http_code=%{http_code} remote_ip=%{remote_ip} total_time=%{time_total}\n' \
      > "$CURL_LOG" 2>&1
    RC=$?
    set -e
    ;;

  *)
    echo "Invalid resolution mode: $RESOLUTION_MODE"
    exit 1
    ;;
esac

cat "$CURL_LOG" || true

HTTP_CODE="$(grep -o 'http_code=[0-9]*' "$CURL_LOG" | tail -1 | cut -d= -f2 || true)"
REMOTE_IP="$(grep -o 'remote_ip=[^ ]*' "$CURL_LOG" | tail -1 | cut -d= -f2 || true)"

if [ "$RC" -eq 0 ] && [ "$HTTP_CODE" = "200" ]; then
  SUCCESS="1"
fi

sleep 2

echo
echo "=== Stopping tcpdump ==="
sudo kill -INT "$TCPDUMP_PID" >/dev/null 2>&1 || true
sudo kill -INT "$DNS_TCPDUMP_PID" >/dev/null 2>&1 || true
wait "$TCPDUMP_PID" >/dev/null 2>&1 || true
wait "$DNS_TCPDUMP_PID" >/dev/null 2>&1 || true
sudo chown "$(id -un):$(id -gn)" "$PCAP" "$DNS_PCAP" "$TCPDUMP_LOG" "$DNS_TCPDUMP_LOG" 2>/dev/null || true

COMPLETED_UTC="$(date -u +%FT%TZ)"

echo "${SESSION_ID},${CONFIG_ID},${MUX_MODE},${RESOLUTION_MODE},${URL},${PCAP},${DNS_PCAP},${CURL_LOG},${SUCCESS},${HTTP_CODE:-NA},${REMOTE_IP:-NA},${STARTED_UTC},${COMPLETED_UTC}" >> "$CATALOG"

echo
echo "=== Session complete ==="
echo "curl_rc=$RC"
echo "success=$SUCCESS"
echo "http_code=${HTTP_CODE:-NA}"
echo "remote_ip=${REMOTE_IP:-NA}"
echo "pcap=$PCAP"
echo "dns_pcap=$DNS_PCAP"
echo "completed_utc=$COMPLETED_UTC"

exit 0
