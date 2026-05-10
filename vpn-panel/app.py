#!/usr/bin/env python3
import json
import os
import re
import socket
import ssl
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import unquote
from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

CONFIG = '/etc/xray/config.json'
SUB_CACHE = '/tmp/vpn-sub-cache'
SUB_URL = 'https://3b8fd492.withblancvpn.online/s/c69ec8720ff24a679ee8573a016669d9'
LOG_FILE = '/var/log/vpn-watchdog.log'
PROBE_PORT = 13344
VPN_STOPPED_FLAG = '/run/vpn-stopped'
_verify_lock = threading.Lock()


# ---------- VPN state helpers ----------

def vpn_is_enabled():
    return not os.path.exists(VPN_STOPPED_FLAG)

def set_vpn_stopped(stopped):
    if stopped:
        try:
            open(VPN_STOPPED_FLAG, 'w').close()
        except Exception:
            pass
    else:
        try:
            os.remove(VPN_STOPPED_FLAG)
        except FileNotFoundError:
            pass


# ---------- Config helpers ----------

def read_config():
    with open(CONFIG) as f:
        return json.load(f)


def current_server():
    cfg = read_config()
    return cfg['outbounds'][0]['settings']['vnext'][0]['address']


def parse_vless_line(line):
    m = re.match(r'vless://([^@]+)@([^:]+):(\d+)\?([^#]*)(?:#(.*))?', line)
    if not m:
        return None
    uuid, host, port, params_str, name = m.groups()
    params = dict(p.split('=', 1) for p in params_str.split('&') if '=' in p)
    isp_m = re.search(r'\(([^)]+)\)', name or '')
    return {
        'uuid': uuid,
        'host': host,
        'port': int(port),
        'name': (name or '').strip(),
        'security': params.get('security', 'tls'),
        'flow': unquote(params.get('flow', '')),
        'fp': params.get('fp', 'chrome'),
        'sni': params.get('sni', host),
        'pbk': params.get('pbk', ''),
        'sid': params.get('sid', ''),
        'alpn': params.get('alpn', 'h2'),
        'net': params.get('type', 'tcp'),
        'ws_host': params.get('host', ''),
        'ws_path': unquote(params.get('path', '/')),
        'allow_insecure': params.get('allowInsecure', '0') == '1',
        'is_whitelist': 'Whitelist' in (name or ''),
        'isp': isp_m.group(1) if isp_m else '',
        'raw': line,
    }


def parse_servers(include_whitelist=True):
    if not os.path.exists(SUB_CACHE):
        return []
    with open(SUB_CACHE) as f:
        lines = f.read().strip().split('\n')
    cur = current_server()
    seen = set()
    servers = []
    for i, line in enumerate(lines):
        parsed = parse_vless_line(line)
        if not parsed:
            continue
        if 'Россия' in parsed['name']:
            continue
        if not include_whitelist and parsed['is_whitelist']:
            continue
        key = (parsed['host'], parsed['port'], parsed['security'],
               parsed['net'], parsed['sni'], parsed['sid'])
        if key in seen:
            continue
        seen.add(key)
        servers.append({
            'id': i + 1,
            'host': parsed['host'],
            'port': parsed['port'],
            'sni': parsed['sni'],
            'name': parsed['name'],
            'security': parsed['security'],
            'net': parsed['net'],
            'is_current': parsed['host'] == cur,
            'is_whitelist': parsed['is_whitelist'],
            'isp': parsed['isp'],
            'raw': parsed['raw'],
        })
    return servers


def tcp_ping(host, port=8443, timeout=3):
    try:
        t0 = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        ms = int((time.time() - t0) * 1000)
        s.close()
        return ms
    except Exception:
        return -1


def tls_ping(host, sni, port=8443, timeout=5):
    try:
        t0 = time.time()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        tls = ctx.wrap_socket(raw, server_hostname=sni)
        ms = int((time.time() - t0) * 1000)
        tls.close()
        return ms
    except Exception:
        return -1


def smart_ping(s):
    return tls_ping(s['host'], s.get('sni', s['host']), s['port'])


def _apply_config():
    """Restart xray only if VPN should be running."""
    if vpn_is_enabled():
        subprocess.run(['systemctl', 'restart', 'xray'], timeout=10)
        time.sleep(2)


def switch_server(vless_line, verify=True):
    parsed = parse_vless_line(vless_line)
    if not parsed:
        raise ValueError('Invalid VLESS line')

    was_enabled = vpn_is_enabled()

    with open(CONFIG) as f:
        old_cfg_text = f.read()

    cfg = json.loads(old_cfg_text)
    out = cfg['outbounds'][0]
    vnext = out['settings']['vnext'][0]
    vnext['address'] = parsed['host']
    vnext['port'] = parsed['port']
    vnext['users'][0]['flow'] = parsed['flow']

    ss = out['streamSettings']
    ss['network'] = parsed['net']
    ss['security'] = parsed['security']

    for key in ('tlsSettings', 'realitySettings', 'wsSettings',
                'tcpSettings', 'httpSettings', 'grpcSettings'):
        ss.pop(key, None)

    if parsed['security'] == 'reality':
        ss['realitySettings'] = {
            'serverName': parsed['sni'],
            'publicKey': parsed['pbk'],
            'shortId': parsed['sid'],
            'fingerprint': parsed['fp'],
        }
    else:
        tls = {
            'serverName': parsed['sni'],
            'fingerprint': parsed['fp'],
        }
        if parsed['sni'] != parsed['host']:
            tls['alpn'] = []
        else:
            tls['alpn'] = [parsed['alpn']]
        if parsed['allow_insecure']:
            tls['allowInsecure'] = True
        ss['tlsSettings'] = tls

    if parsed['net'] == 'ws':
        ws = {'path': parsed['ws_path']}
        if parsed['ws_host']:
            ws['headers'] = {'Host': parsed['ws_host']}
        ss['wsSettings'] = ws

    with open(CONFIG, 'w') as f:
        json.dump(cfg, f, indent=2)

    # If VPN was intentionally stopped, just update config without restarting
    if not was_enabled:
        return

    _tproxy_enable()
    subprocess.run(['systemctl', 'restart', 'xray'], timeout=10)
    time.sleep(2)

    if verify:
        alive, ip = _check_tunnel_alive(timeout=8)
        if not alive:
            with open(CONFIG, 'w') as f:
                f.write(old_cfg_text)
            subprocess.run(['systemctl', 'restart', 'xray'], timeout=10)
            time.sleep(2)
            raise RuntimeError(f'Сервер {parsed["host"]} недоступен — откатил на прошлый конфиг')


def find_best(servers):
    best, best_ms = None, 99999

    def ping_one(s):
        return s, smart_ping(s)

    with ThreadPoolExecutor(max_workers=20) as pool:
        for s, ms in pool.map(ping_one, servers):
            if 0 <= ms < best_ms:
                best, best_ms = s, ms

    return best, best_ms


def _build_probe_config(parsed):
    cfg = {
        'log': {'loglevel': 'warning'},
        'inbounds': [{
            'tag': 'http-in',
            'port': PROBE_PORT,
            'listen': '127.0.0.1',
            'protocol': 'http',
            'settings': {},
        }],
        'outbounds': [{
            'tag': 'proxy',
            'protocol': 'vless',
            'settings': {
                'vnext': [{
                    'address': parsed['host'],
                    'port': parsed['port'],
                    'users': [{
                        'id': parsed['uuid'],
                        'encryption': 'none',
                        'flow': parsed['flow'],
                    }],
                }],
            },
            'streamSettings': {
                'network': parsed['net'],
                'security': parsed['security'],
            },
        }],
    }
    ss = cfg['outbounds'][0]['streamSettings']
    if parsed['security'] == 'reality':
        ss['realitySettings'] = {
            'serverName': parsed['sni'],
            'publicKey': parsed['pbk'],
            'shortId': parsed['sid'],
            'fingerprint': parsed['fp'],
        }
    else:
        tls = {'serverName': parsed['sni'], 'fingerprint': parsed['fp']}
        if parsed['sni'] != parsed['host']:
            tls['alpn'] = []
        else:
            tls['alpn'] = [parsed['alpn']]
        if parsed['allow_insecure']:
            tls['allowInsecure'] = True
        ss['tlsSettings'] = tls
    if parsed['net'] == 'ws':
        ws = {'path': parsed['ws_path']}
        if parsed['ws_host']:
            ws['headers'] = {'Host': parsed['ws_host']}
        ss['wsSettings'] = ws
    return cfg


def verify_server(vless_line, timeout=8):
    parsed = parse_vless_line(vless_line)
    if not parsed:
        return {'ms': -1, 'ip': '', 'ok': False, 'error': 'parse'}

    with _verify_lock:
        cfg = _build_probe_config(parsed)
        cfg_path = f'/tmp/xray-probe-{os.getpid()}.json'
        try:
            with open(cfg_path, 'w') as f:
                json.dump(cfg, f)
        except Exception as e:
            return {'ms': -1, 'ip': '', 'ok': False, 'error': f'cfg: {e}'}

        proc = None
        try:
            proc = subprocess.Popen(
                ['xray', '-c', cfg_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            ready = False
            for _ in range(30):
                time.sleep(0.1)
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.3)
                        s.connect(('127.0.0.1', PROBE_PORT))
                    ready = True
                    break
                except Exception:
                    pass
            if not ready:
                return {'ms': -1, 'ip': '', 'ok': False, 'error': 'xray-not-up'}

            t0 = time.time()
            r = subprocess.run(
                ['curl', '-4', '-s', '--max-time', str(timeout),
                 '-x', f'http://127.0.0.1:{PROBE_PORT}',
                 'https://api.ipify.org'],
                capture_output=True, text=True, timeout=timeout + 2,
            )
            ms = int((time.time() - t0) * 1000)
            ip = (r.stdout or '').strip()
            if ip and ip.count('.') == 3:
                return {'ms': ms, 'ip': ip, 'ok': True}
            return {'ms': -1, 'ip': '', 'ok': False, 'error': 'no-ip'}
        except Exception as e:
            return {'ms': -1, 'ip': '', 'ok': False, 'error': str(e)}
        finally:
            if proc:
                try:
                    proc.terminate()
                    proc.wait(timeout=2)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass
            try:
                os.remove(cfg_path)
            except Exception:
                pass


def find_best_verified(servers, top_n=6):
    pings = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        for s, ms in pool.map(lambda x: (x, smart_ping(x)), servers):
            if ms > 0:
                pings.append((s, ms))
    pings.sort(key=lambda x: x[1])

    best, best_ms, best_ip = None, 99999, ''
    tested = []
    for s, _tls in pings[:top_n]:
        line = find_vless_line(s['host'], s.get('sni', ''))
        if not line:
            continue
        result = verify_server(line)
        tested.append({'host': s['host'], 'name': s['name'], 'ok': result['ok'],
                       'ms': result['ms'], 'ip': result['ip']})
        if result['ok'] and 0 < result['ms'] < best_ms:
            best, best_ms, best_ip = s, result['ms'], result['ip']
    return best, best_ms, best_ip, tested


def _check_tunnel_alive(timeout=8):
    try:
        r = subprocess.run(
            ['curl', '-4', '-s', '--max-time', str(timeout), 'https://api.ipify.org'],
            capture_output=True, text=True, timeout=timeout + 2,
        )
        ip = (r.stdout or '').strip()
        if not ip or ip.count('.') != 3:
            return False, ''
        try:
            r2 = subprocess.run(
                ['curl', '-s', '--max-time', '4',
                 f'http://ip-api.com/json/{ip}?fields=countryCode'],
                capture_output=True, text=True, timeout=6,
            )
            cc = json.loads(r2.stdout or '{}').get('countryCode', '')
            if cc == 'RU':
                return False, ip
        except Exception:
            pass
        return True, ip
    except Exception:
        return False, ''


def find_vless_line(host, sni_hint=''):
    if not os.path.exists(SUB_CACHE):
        return None
    with open(SUB_CACHE) as f:
        lines = f.read().strip().split('\n')
    for line in lines:
        parsed = parse_vless_line(line)
        if not parsed:
            continue
        if parsed['host'] == host:
            if sni_hint and parsed['sni'] != sni_hint:
                continue
            return line
    return None


def refresh_subscription():
    try:
        r = subprocess.run(
            ['curl', '-sL', '--max-time', '15', SUB_URL],
            capture_output=True, text=True, timeout=20
        )
        if r.stdout.strip():
            import base64
            decoded = base64.b64decode(r.stdout.strip()).decode('utf-8', errors='ignore')
            if decoded.startswith('vless://'):
                with open(SUB_CACHE, 'w') as f:
                    f.write(decoded)
                return True
    except Exception:
        pass
    return False


# ---------- Routing helpers ----------

def is_ip_entry(entry):
    return bool(re.match(r'^[\d:./]+$', entry))


def _find_custom_rule(rules, outbound_tag, entry_type):
    """Find user-added (non-geo, non-catchall) rule for given outbound+type."""
    for rule in rules:
        if rule.get('outboundTag') != outbound_tag:
            continue
        if entry_type not in rule:
            continue
        if 'protocol' in rule:
            continue
        entries = rule.get(entry_type, [])
        if any(e.startswith('geoip:') or e.startswith('geosite:') or
               e in ('0.0.0.0/0', '::/0') for e in entries):
            continue
        return rule
    return None


def get_custom_routing(cfg=None):
    if cfg is None:
        cfg = read_config()
    rules = cfg.get('routing', {}).get('rules', [])
    out = {'direct_domains': [], 'direct_ips': [], 'proxy_domains': [], 'proxy_ips': []}
    for tag, dk, ik in [('direct', 'direct_domains', 'direct_ips'),
                        ('proxy',  'proxy_domains',  'proxy_ips')]:
        r = _find_custom_rule(rules, tag, 'domain')
        if r:
            out[dk] = list(r.get('domain', []))
        r = _find_custom_rule(rules, tag, 'ip')
        if r:
            out[ik] = list(r.get('ip', []))
    return out


def modify_routing(action, target, entry):
    """action: add|remove  target: direct|proxy  entry: domain or IP."""
    cfg = read_config()
    rules = cfg['routing']['rules']
    entry_type = 'ip' if is_ip_entry(entry) else 'domain'

    # Find catch-all rule index
    catchall_idx = len(rules)
    for i, rule in enumerate(rules):
        if (rule.get('outboundTag') == 'proxy' and
                '0.0.0.0/0' in rule.get('ip', [])):
            catchall_idx = i
            break

    # proxy custom rules go at index 1 (after DNS, before private-IP rule) so
    # they can override category-ru/geoip-ru if needed.
    # direct custom rules go just before the catch-all.
    insert_at = 1 if target == 'proxy' else catchall_idx

    custom = _find_custom_rule(rules, target, entry_type)
    if action == 'add':
        if custom is not None:
            if entry not in custom[entry_type]:
                custom[entry_type].append(entry)
        else:
            rules.insert(insert_at, {
                'type': 'field', entry_type: [entry], 'outboundTag': target,
            })
    elif action == 'remove':
        if custom is not None:
            try:
                custom[entry_type].remove(entry)
            except ValueError:
                pass
            if not custom[entry_type]:
                rules.remove(custom)

    with open(CONFIG, 'w') as f:
        json.dump(cfg, f, indent=2)
    _apply_config()


# ---------- iptables helpers ----------

def _tproxy_disable():
    subprocess.run(['iptables', '-t', 'mangle', '-D', 'PREROUTING', '-j', 'XRAY'],
                   capture_output=True)
    subprocess.run(['iptables', '-t', 'mangle', '-D', 'OUTPUT', '-j', 'XRAY_SELF'],
                   capture_output=True)


def _tproxy_enable():
    r = subprocess.run(['iptables', '-t', 'mangle', '-C', 'PREROUTING', '-j', 'XRAY'],
                       capture_output=True)
    if r.returncode != 0:
        subprocess.run(['iptables', '-t', 'mangle', '-I', 'PREROUTING', '1', '-j', 'XRAY'])
    r = subprocess.run(['iptables', '-t', 'mangle', '-C', 'OUTPUT', '-j', 'XRAY_SELF'],
                       capture_output=True)
    if r.returncode != 0:
        subprocess.run(['iptables', '-t', 'mangle', '-I', 'OUTPUT', '1', '-j', 'XRAY_SELF'])


# ---------- Routes ----------

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    r = subprocess.run(['systemctl', 'is-active', 'xray'], capture_output=True, text=True)
    xray_active = r.stdout.strip() == 'active'
    server = current_server()
    ip = ''
    geo = {}
    latency = None

    if xray_active:
        try:
            t0 = time.time()
            r = subprocess.run(
                ['curl', '-4', '-s', '--max-time', '5', 'https://api.ipify.org'],
                capture_output=True, text=True, timeout=8
            )
            ip = r.stdout.strip()
            latency = int((time.time() - t0) * 1000)
            if ip:
                r = subprocess.run(
                    ['curl', '-s', '--max-time', '3',
                     f'http://ip-api.com/json/{ip}?fields=country,city,countryCode'],
                    capture_output=True, text=True, timeout=5
                )
                geo = json.loads(r.stdout)
        except Exception:
            pass

    r = subprocess.run(['systemctl', 'is-active', 'vpn-watchdog.timer'],
                       capture_output=True, text=True)
    watchdog = r.stdout.strip() == 'active'

    return jsonify({
        'xray_active': xray_active,
        'vpn_enabled': vpn_is_enabled(),
        'server': server,
        'ip': ip,
        'geo': geo,
        'latency': latency,
        'watchdog': watchdog,
    })


@app.route('/api/servers')
def api_servers():
    """Return server list immediately without pinging."""
    servers = parse_servers(include_whitelist=True)
    cdn = [s for s in servers if not s['is_whitelist']]
    wl  = [s for s in servers if s['is_whitelist']]
    for s in cdn + wl:
        s.pop('raw', None)
    return jsonify({'cdn': cdn, 'whitelist': wl})


@app.route('/api/ping-servers', methods=['POST'])
def api_ping_servers():
    """Async ping all servers. Returns {host: ms} map."""
    servers = parse_servers(include_whitelist=True)

    def ping_one(s):
        return s['host'], smart_ping(s)

    with ThreadPoolExecutor(max_workers=20) as pool:
        results = dict(pool.map(ping_one, servers))

    return jsonify(results)


@app.route('/api/switch', methods=['POST'])
def api_switch():
    data = request.json or {}
    host = data.get('host', '')
    sni = data.get('sni', '')
    if not host:
        return jsonify({'error': 'host required'}), 400

    target_line = find_vless_line(host, sni)
    if not target_line:
        return jsonify({'error': 'server not found'}), 404

    try:
        switch_server(target_line)
        return jsonify({'ok': True, 'server': host})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/best', methods=['POST'])
def api_best():
    data = request.json or {}
    whitelist = data.get('whitelist', False)
    isp = data.get('isp', '')
    verify = data.get('verify', whitelist)

    all_servers = parse_servers(include_whitelist=True)
    if whitelist:
        servers = [s for s in all_servers if s['is_whitelist']]
        if isp:
            servers = [s for s in servers if s['isp'] == isp]
    else:
        servers = [s for s in all_servers if not s['is_whitelist']]

    if not servers:
        return jsonify({'error': 'Нет доступных серверов'}), 500

    best_ip = ''
    tested = []
    if verify:
        best, best_ms, best_ip, tested = find_best_verified(servers, top_n=6)
    else:
        best, best_ms = find_best(servers)
    if not best:
        return jsonify({'error': 'Все серверы недоступны', 'tested': tested}), 500

    target_line = find_vless_line(best['host'], best.get('sni', ''))
    if not target_line:
        if not os.path.exists(SUB_CACHE):
            return jsonify({'error': 'no cache'}), 500
        with open(SUB_CACHE) as f:
            for line in f.read().strip().split('\n'):
                p = parse_vless_line(line)
                if p and p['host'] == best['host']:
                    target_line = line
                    break
    if not target_line:
        return jsonify({'error': 'server line not found'}), 500

    try:
        switch_server(target_line)
    except Exception as e:
        return jsonify({'error': str(e), 'tested': tested}), 500

    return jsonify({
        'ok': True,
        'server': best['host'],
        'name': best['name'],
        'ping': best_ms,
        'verified_ip': best_ip,
        'verified': verify,
        'is_whitelist': best['is_whitelist'],
        'tested': tested,
    })


@app.route('/api/verify', methods=['POST'])
def api_verify():
    data = request.json or {}
    host = data.get('host', '')
    sni = data.get('sni', '')
    if not host:
        host = current_server()
    line = find_vless_line(host, sni)
    if not line:
        return jsonify({'error': f'VLESS line not found for {host}'}), 404
    result = verify_server(line)
    parsed = parse_vless_line(line)
    result['host'] = host
    result['name'] = parsed['name'] if parsed else ''
    return jsonify(result)


@app.route('/api/action', methods=['POST'])
def api_action():
    action = (request.json or {}).get('action', '')
    if action not in ('start', 'stop', 'restart'):
        return jsonify({'error': 'invalid action'}), 400
    if action == 'stop':
        subprocess.run(['systemctl', 'stop', 'xray'], timeout=10)
        _tproxy_disable()
        set_vpn_stopped(True)
    elif action == 'start':
        set_vpn_stopped(False)
        _tproxy_enable()
        subprocess.run(['systemctl', 'start', 'xray'], timeout=10)
    else:
        subprocess.run(['systemctl', 'restart', 'xray'], timeout=10)
    time.sleep(2)
    return jsonify({'ok': True})


@app.route('/api/watchdog', methods=['POST'])
def api_watchdog():
    enabled = (request.json or {}).get('enabled', False)
    if enabled:
        subprocess.run(['systemctl', 'enable', '--now', 'vpn-watchdog.timer'], timeout=10)
    else:
        subprocess.run(['systemctl', 'disable', '--now', 'vpn-watchdog.timer'], timeout=10)
    return jsonify({'ok': True, 'enabled': enabled})


@app.route('/api/refresh-sub', methods=['POST'])
def api_refresh_sub():
    ok = refresh_subscription()
    return jsonify({'ok': ok})


@app.route('/api/logs')
def api_logs():
    try:
        with open(LOG_FILE) as f:
            lines = f.readlines()[-50:]
        return jsonify({'lines': [l.strip() for l in lines if l.strip()]})
    except Exception:
        return jsonify({'lines': []})


@app.route('/api/routing')
def api_routing_get():
    return jsonify(get_custom_routing())


@app.route('/api/routing', methods=['POST'])
def api_routing_post():
    data = request.json or {}
    action = data.get('action', '')
    target = data.get('target', '')
    entry  = data.get('entry', '').strip()
    if action not in ('add', 'remove') or target not in ('direct', 'proxy') or not entry:
        return jsonify({'error': 'invalid params'}), 400
    modify_routing(action, target, entry)
    return jsonify({'ok': True, 'routing': get_custom_routing()})


@app.route('/api/pi-stats')
def api_pi_stats():
    def _read(cmd):
        try:
            return subprocess.check_output(cmd, shell=True, text=True, timeout=3).strip()
        except Exception:
            return '—'

    temp  = _read("vcgencmd measure_temp 2>/dev/null | sed 's/temp=//'")
    cpu   = _read("top -bn1 | grep 'Cpu(s)' | awk '{printf \"%.1f\", $2+$4}'")
    ram   = _read("free -m | awk 'NR==2{printf \"%.1f%% (%d/%d MB)\", $3*100/$2, $3, $2}'")
    disk  = _read("df -h / | awk 'NR==2{printf \"%s (%s / %s)\", $5, $3, $2}'")
    up    = _read("uptime -p | sed 's/up //'")
    load  = _read("cat /proc/loadavg | awk '{print $1, $2, $3}'")
    freq  = _read("vcgencmd measure_clock arm 2>/dev/null | sed 's/frequency(.*=//; s/$//' | awk '{printf \"%.0f MHz\", $1/1000000}'")

    return jsonify({
        'temp': temp, 'cpu': cpu, 'ram': ram,
        'disk': disk, 'uptime': up, 'load': load, 'freq': freq,
    })


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
