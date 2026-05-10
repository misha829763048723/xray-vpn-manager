#!/usr/bin/env python3
"""VPN Telegram bot — owner-only remote control."""
import json
import logging
import os
import sys
import time
import traceback
from typing import Any, Dict, Optional

import requests

TOKEN = os.environ.get('TG_BOT_TOKEN', '').strip()
ADMIN_ID = int(os.environ.get('TG_ADMIN_ID', '0') or '0')
PANEL_URL = os.environ.get('PANEL_URL', 'http://127.0.0.1:8080').rstrip('/')

if not TOKEN or not ADMIN_ID:
    print('FATAL: TG_BOT_TOKEN and TG_ADMIN_ID env vars must be set', file=sys.stderr)
    sys.exit(2)

API = f'https://api.telegram.org/bot{TOKEN}'

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('vpn-bot')

SESSION = requests.Session()


# ---------- Telegram helpers ----------

def tg(method: str, **params) -> Dict[str, Any]:
    try:
        r = SESSION.post(f'{API}/{method}', json=params, timeout=70)
        return r.json()
    except Exception as e:
        log.warning(f'tg {method}: {e}')
        return {'ok': False, 'error': str(e)}


def send(chat_id: int, text: str, **kw) -> Dict[str, Any]:
    return tg('sendMessage', chat_id=chat_id, text=text,
              parse_mode='HTML', disable_web_page_preview=True, **kw)


def edit(chat_id: int, message_id: int, text: str, **kw) -> Dict[str, Any]:
    return tg('editMessageText', chat_id=chat_id, message_id=message_id,
              text=text, parse_mode='HTML', disable_web_page_preview=True, **kw)


def answer_cb(cb_id: str, text: str = '', show_alert: bool = False):
    return tg('answerCallbackQuery', callback_query_id=cb_id,
              text=text[:200], show_alert=show_alert)


# ---------- Panel API helpers ----------

def panel_get(path: str, timeout: int = 30) -> Optional[Dict[str, Any]]:
    try:
        r = SESSION.get(f'{PANEL_URL}/api/{path}', timeout=timeout)
        return r.json()
    except Exception as e:
        log.warning(f'panel GET {path}: {e}')
        return None


def panel_post(path: str, data: Optional[Dict] = None,
               timeout: int = 90) -> Dict[str, Any]:
    try:
        r = SESSION.post(f'{PANEL_URL}/api/{path}',
                         json=data or {}, timeout=timeout)
        return r.json()
    except Exception as e:
        log.warning(f'panel POST {path}: {e}')
        return {'error': str(e)}


# ---------- UI ----------

def status_text(d: Dict[str, Any]) -> str:
    if not d:
        return '⚠ Панель недоступна'
    active = d.get('xray_active')
    ip = d.get('ip') or ''
    if active and ip:
        icon, state = '🟢', 'Подключено'
    elif active:
        icon, state = '🟡', 'Запущен, нет связи'
    else:
        icon, state = '🔴', 'Остановлен'
    geo = d.get('geo') or {}
    loc = ''
    if geo.get('city'):
        loc = f"{geo['city']}, {geo.get('country', '')}"
    elif geo.get('country'):
        loc = geo['country']
    lat = d.get('latency')
    lat_s = f'{lat} мс' if lat else '—'
    return (
        f'{icon} <b>{state}</b>\n\n'
        f'<b>Сервер:</b> <code>{d.get("server", "—")}</code>\n'
        f'<b>IP:</b> <code>{ip or "—"}</code>\n'
        f'<b>Локация:</b> {loc or "—"}\n'
        f'<b>Латентность:</b> {lat_s}\n'
        f'<b>Watchdog:</b> {"✅ on" if d.get("watchdog") else "⚪ off"}'
    )


def main_keyboard(d: Dict[str, Any]) -> Dict:
    active = bool(d and d.get('xray_active'))
    wd = bool(d and d.get('watchdog'))
    return {'inline_keyboard': [
        [
            {'text': '🔄 Restart', 'callback_data': 'act:restart'},
            ({'text': '🔴 Stop', 'callback_data': 'act:stop'}
             if active else
             {'text': '🟢 Start', 'callback_data': 'act:start'}),
            {'text': '✅ Verify', 'callback_data': 'verify:cur'},
        ],
        [
            {'text': '🚀 Best CDN', 'callback_data': 'best:cdn'},
            {'text': '🎯 Best WL', 'callback_data': 'best:wl'},
        ],
        [
            {'text': '📋 CDN', 'callback_data': 'list:cdn:0'},
            {'text': '📋 WL', 'callback_data': 'list:wl:0'},
            {'text': '🔀 Туннель', 'callback_data': 'routing'},
        ],
        [
            ({'text': '🐕 WD off', 'callback_data': 'wd:off'}
             if wd else
             {'text': '🐕 WD on', 'callback_data': 'wd:on'}),
            {'text': '📜 Logs', 'callback_data': 'logs'},
            {'text': '🔃 Refresh', 'callback_data': 'status'},
        ],
        [
            {'text': '🖥 Pi stats', 'callback_data': 'pistats'},
        ],
    ]}


def server_list_keyboard(servers, page: int, kind: str, per_page: int = 8) -> Dict:
    start = page * per_page
    chunk = servers[start:start + per_page]
    rows = []
    for s in chunk:
        cur = ' •' if s.get('is_current') else ''
        name = s.get('name') or s.get('host') or '?'
        if len(name) > 36:
            name = name[:34] + '…'
        label = f'{name}{cur}'
        rows.append([{'text': label,
                      'callback_data': f'sw:{kind}:{s["host"]}'}])
    nav = []
    if page > 0:
        nav.append({'text': '◀', 'callback_data': f'list:{kind}:{page - 1}'})
    if start + per_page < len(servers):
        nav.append({'text': '▶', 'callback_data': f'list:{kind}:{page + 1}'})
    nav.append({'text': '⬅ back', 'callback_data': 'status'})
    rows.append(nav)
    return {'inline_keyboard': rows}


def routing_keyboard(routing: Dict) -> Dict:
    """Build keyboard for routing management."""
    rows = []

    direct = routing.get('direct_domains', []) + routing.get('direct_ips', [])
    proxy  = routing.get('proxy_domains', [])  + routing.get('proxy_ips', [])

    # Direct entries (remove buttons)
    if direct:
        for entry in direct[:8]:
            label = ('🏠 ' + entry)[:48]
            rows.append([{'text': label, 'callback_data': f'rt:rm:direct:{entry}'}])
    # Proxy entries (remove buttons)
    if proxy:
        for entry in proxy[:8]:
            label = ('🔒 ' + entry)[:48]
            rows.append([{'text': label, 'callback_data': f'rt:rm:proxy:{entry}'}])

    rows.append([
        {'text': '⬅ back', 'callback_data': 'status'},
        {'text': '🔃 Refresh', 'callback_data': 'routing'},
    ])
    return {'inline_keyboard': rows}


def routing_text(routing: Dict) -> str:
    direct = routing.get('direct_domains', []) + routing.get('direct_ips', [])
    proxy  = routing.get('proxy_domains', [])  + routing.get('proxy_ips', [])

    lines = ['🔀 <b>Раздельное туннелирование</b>\n',
             '<b>Встроенные правила (напрямую):</b>',
             '  • geosite:category-ru  • geoip:ru  • geoip:private\n']

    lines.append('<b>🏠 Напрямую (обход VPN):</b>')
    if direct:
        lines += [f'  <code>{e}</code>' for e in direct]
    else:
        lines.append('  <i>пусто</i>')

    lines.append('\n<b>🔒 Через VPN принудительно:</b>')
    if proxy:
        lines += [f'  <code>{e}</code>' for e in proxy]
    else:
        lines.append('  <i>пусто</i>')

    lines.append('\n<i>Нажмите запись чтобы удалить.</i>')
    lines.append('<i>Для добавления:</i>')
    lines.append('<code>/direct example.com</code> — обход VPN')
    lines.append('<code>/proxy example.com</code> — через VPN')
    return '\n'.join(lines)


# ---------- Auth ----------

def is_owner(user_id: int) -> bool:
    return user_id == ADMIN_ID


# ---------- Handlers ----------

def cmd_status(chat_id: int, message_id: Optional[int] = None):
    d = panel_get('status') or {}
    text = status_text(d)
    kb = main_keyboard(d)
    if message_id:
        edit(chat_id, message_id, text, reply_markup=kb)
    else:
        send(chat_id, text, reply_markup=kb)


def cmd_help(chat_id: int):
    text = (
        '🤖 <b>VPN Bot</b>\n\n'
        '<b>Команды:</b>\n'
        '/status — статус и кнопки управления\n'
        '/best — лучший CDN\n'
        '/best_wl — лучший Whitelist (с реальной проверкой)\n'
        '/verify — реальная проверка текущего сервера\n'
        '/restart — перезапуск xray\n'
        '/stop, /vpn_on — VPN on/off\n'
        '/watchdog [on|off] — авто-переключение\n'
        '/logs — последние строки watchdog\n'
        '/servers — список CDN с кнопками\n'
        '/wl — список Whitelist с кнопками\n'
        '/pi — статус Raspberry Pi (температура, CPU, RAM, диск)\n'
        '/routing — управление раздельным туннелированием\n'
        '/direct &lt;домен/IP&gt; — добавить в обход VPN\n'
        '/proxy &lt;домен/IP&gt; — добавить в принудительный VPN\n'
        '/refresh_sub — обновить подписку\n'
        '/help — эта справка'
    )
    send(chat_id, text)


def cmd_verify(chat_id: int):
    msg = send(chat_id, '⏳ Реальная проверка текущего сервера…')
    mid = msg.get('result', {}).get('message_id')
    r = panel_post('verify', {}, timeout=20)
    if r.get('ok'):
        text = (
            f'✅ <b>Туннель работает</b>\n'
            f'Сервер: <code>{r.get("host", "—")}</code>\n'
            f'Имя: {r.get("name", "—")}\n'
            f'Внешний IP: <code>{r.get("ip", "—")}</code>\n'
            f'Латентность: {r.get("ms", "—")} мс'
        )
    else:
        text = (
            f'❌ <b>Туннель НЕ работает</b>\n'
            f'Сервер: <code>{r.get("host", "—")}</code>\n'
            f'Ошибка: {r.get("error", "?")}'
        )
    if mid:
        edit(chat_id, mid, text)
    else:
        send(chat_id, text)


def cmd_action(chat_id: int, action: str):
    msg = send(chat_id, f'⏳ {action}…')
    mid = msg.get('result', {}).get('message_id')
    r = panel_post('action', {'action': action}, timeout=20)
    text = '✅ Готово' if r.get('ok') else f'❌ Ошибка: {r.get("error", "?")}'
    if mid:
        edit(chat_id, mid, text)
    time.sleep(1.5)
    cmd_status(chat_id)


def cmd_best(chat_id: int, whitelist: bool):
    label = 'Whitelist' if whitelist else 'CDN'
    note = ' (с реальной проверкой, ~30с)' if whitelist else ''
    msg = send(chat_id, f'⏳ Ищу лучший {label}{note}…')
    mid = msg.get('result', {}).get('message_id')
    r = panel_post('best', {'whitelist': whitelist}, timeout=120)
    if r.get('ok'):
        verified = ' (verified)' if r.get('verified') else ''
        ip = r.get('verified_ip')
        ip_s = f'\nВнешний IP: <code>{ip}</code>' if ip else ''
        text = (
            f'✅ Переключено{verified}\n'
            f'<b>{r.get("name", "—")}</b>\n'
            f'<code>{r.get("server", "—")}</code>\n'
            f'Пинг: {r.get("ping", "—")} мс{ip_s}'
        )
        tested = r.get('tested') or []
        if tested:
            lines = []
            for t in tested[:6]:
                mark = '✅' if t.get('ok') else '❌'
                ms = t.get('ms', -1)
                ms_s = f'{ms}мс' if ms > 0 else '—'
                lines.append(f'{mark} {ms_s} — {t.get("name", t.get("host", "?"))[:40]}')
            text += '\n\n<b>Проверено:</b>\n' + '\n'.join(lines)
    else:
        text = f'❌ {r.get("error", "?")}'
    if mid:
        edit(chat_id, mid, text)
    time.sleep(1)
    cmd_status(chat_id)


def cmd_logs(chat_id: int):
    d = panel_get('logs') or {}
    lines = d.get('lines') or []
    if not lines:
        send(chat_id, '📜 Лог пуст')
        return
    tail = lines[-20:]
    text = '<b>📜 Watchdog (последние 20):</b>\n<pre>' + '\n'.join(
        l.replace('<', '&lt;').replace('>', '&gt;')[:120] for l in tail
    ) + '</pre>'
    send(chat_id, text)


def cmd_watchdog(chat_id: int, arg: str):
    if arg in ('on', 'off'):
        r = panel_post('watchdog', {'enabled': arg == 'on'}, timeout=20)
        send(chat_id, f'🐕 Watchdog {arg.upper()}' if r.get('ok')
             else f'❌ {r.get("error", "?")}')
    else:
        d = panel_get('status') or {}
        send(chat_id,
             f'🐕 Watchdog: {"ON" if d.get("watchdog") else "OFF"}\n'
             f'Используй: /watchdog on  или  /watchdog off')


def cmd_refresh_sub(chat_id: int):
    msg = send(chat_id, '⏳ Обновляю подписку…')
    mid = msg.get('result', {}).get('message_id')
    r = panel_post('refresh-sub', {}, timeout=30)
    text = '✅ Подписка обновлена' if r.get('ok') else '❌ Не удалось обновить'
    if mid:
        edit(chat_id, mid, text)


def cmd_list(chat_id: int, kind: str, page: int = 0,
             message_id: Optional[int] = None):
    msg_text = '⏳ Загружаю серверы…'
    if message_id:
        edit(chat_id, message_id, msg_text)
        mid = message_id
    else:
        m = send(chat_id, msg_text)
        mid = m.get('result', {}).get('message_id')
    d = panel_get('servers', timeout=30) or {}
    servers = d.get('whitelist' if kind == 'wl' else 'cdn') or []
    if not servers:
        if mid:
            edit(chat_id, mid, '⚠ Нет серверов')
        return
    title = '📋 <b>Whitelist</b>' if kind == 'wl' else '📋 <b>CDN</b>'
    title += f'  ({len(servers)})'
    if mid:
        edit(chat_id, mid, title,
             reply_markup=server_list_keyboard(servers, page, kind))


def cmd_pi_stats(chat_id: int, message_id: Optional[int] = None):
    d = panel_get('pi-stats', timeout=10) or {}
    if not d:
        text = '⚠ Не удалось получить статус Pi'
    else:
        text = (
            '🖥 <b>Raspberry Pi</b>\n\n'
            f'🌡 <b>Температура:</b> {d.get("temp", "—")}\n'
            f'⚙️ <b>CPU:</b> {d.get("cpu", "—")}%'
            + (f'  <i>({d.get("freq", "")})</i>' if d.get("freq") else '') + '\n'
            f'📊 <b>Нагрузка:</b> {d.get("load", "—")}\n'
            f'🧠 <b>RAM:</b> {d.get("ram", "—")}\n'
            f'💾 <b>Диск:</b> {d.get("disk", "—")}\n'
            f'⏱ <b>Uptime:</b> {d.get("uptime", "—")}'
        )
    if message_id:
        edit(chat_id, message_id, text)
    else:
        send(chat_id, text)


def cmd_routing(chat_id: int, message_id: Optional[int] = None):
    d = panel_get('routing') or {}
    text = routing_text(d)
    kb = routing_keyboard(d)
    if message_id:
        edit(chat_id, message_id, text, reply_markup=kb)
    else:
        send(chat_id, text, reply_markup=kb)


def cmd_routing_add(chat_id: int, target: str, entry: str):
    entry = entry.strip()
    if not entry:
        send(chat_id, f'Использование: /{target} example.com')
        return
    r = panel_post('routing', {'action': 'add', 'target': target, 'entry': entry}, timeout=15)
    if r.get('ok'):
        label = 'обход VPN' if target == 'direct' else 'принудительно через VPN'
        send(chat_id, f'✅ <code>{entry}</code> → {label}')
    else:
        send(chat_id, f'❌ {r.get("error", "?")}')


def cmd_switch(chat_id: int, kind: str, host: str,
               message_id: Optional[int] = None):
    if message_id:
        edit(chat_id, message_id, f'⏳ Переключаюсь на <code>{host}</code>…')
    r = panel_post('switch', {'host': host}, timeout=30)
    if r.get('ok'):
        text = f'✅ Переключено на <code>{host}</code>'
    else:
        text = f'❌ {r.get("error", "?")}'
    if message_id:
        edit(chat_id, message_id, text)
    else:
        send(chat_id, text)
    time.sleep(1.5)
    cmd_status(chat_id)


# ---------- Routing ----------

def handle_command(chat_id: int, text: str):
    parts = text.strip().split(maxsplit=1)
    cmd = parts[0].split('@')[0].lower()
    arg = parts[1] if len(parts) > 1 else ''

    if cmd in ('/start', '/help'):
        cmd_help(chat_id)
        cmd_status(chat_id)
    elif cmd == '/status':
        cmd_status(chat_id)
    elif cmd == '/verify':
        cmd_verify(chat_id)
    elif cmd == '/restart':
        cmd_action(chat_id, 'restart')
    elif cmd == '/stop':
        cmd_action(chat_id, 'stop')
    elif cmd in ('/vpn_on', '/on'):
        cmd_action(chat_id, 'start')
    elif cmd == '/best':
        cmd_best(chat_id, whitelist=False)
    elif cmd in ('/best_wl', '/bestwl'):
        cmd_best(chat_id, whitelist=True)
    elif cmd == '/logs':
        cmd_logs(chat_id)
    elif cmd == '/watchdog':
        cmd_watchdog(chat_id, arg.strip().lower())
    elif cmd in ('/refresh_sub', '/refreshsub'):
        cmd_refresh_sub(chat_id)
    elif cmd == '/servers':
        cmd_list(chat_id, 'cdn', 0)
    elif cmd == '/wl':
        cmd_list(chat_id, 'wl', 0)
    elif cmd in ('/pi', '/pistat', '/pistats'):
        cmd_pi_stats(chat_id)
    elif cmd == '/routing':
        cmd_routing(chat_id)
    elif cmd == '/direct':
        cmd_routing_add(chat_id, 'direct', arg)
    elif cmd == '/proxy':
        cmd_routing_add(chat_id, 'proxy', arg)
    else:
        send(chat_id, f'Неизвестная команда: <code>{cmd}</code>\nСм. /help')


def handle_callback(cq: Dict[str, Any]):
    cb_id = cq['id']
    data = cq.get('data', '')
    msg = cq.get('message') or {}
    chat_id = msg.get('chat', {}).get('id')
    message_id = msg.get('message_id')
    if not chat_id or not message_id:
        answer_cb(cb_id)
        return
    answer_cb(cb_id)

    try:
        if data == 'status':
            cmd_status(chat_id, message_id)
        elif data == 'logs':
            cmd_logs(chat_id)
        elif data == 'verify:cur':
            cmd_verify(chat_id)
        elif data.startswith('act:'):
            cmd_action(chat_id, data.split(':', 1)[1])
        elif data == 'best:cdn':
            cmd_best(chat_id, whitelist=False)
        elif data == 'best:wl':
            cmd_best(chat_id, whitelist=True)
        elif data.startswith('wd:'):
            cmd_watchdog(chat_id, data.split(':', 1)[1])
            cmd_status(chat_id, message_id)
        elif data.startswith('list:'):
            _, kind, page = data.split(':')
            cmd_list(chat_id, kind, int(page), message_id)
        elif data.startswith('sw:'):
            _, kind, host = data.split(':', 2)
            cmd_switch(chat_id, kind, host, message_id)
        elif data == 'routing':
            cmd_routing(chat_id, message_id)
        elif data == 'pistats':
            cmd_pi_stats(chat_id, message_id)
        elif data.startswith('rt:rm:'):
            # rt:rm:<target>:<entry>
            parts = data.split(':', 3)
            if len(parts) == 4:
                _, _, target, entry = parts
                r = panel_post('routing', {'action': 'remove', 'target': target, 'entry': entry}, timeout=15)
                if r.get('ok'):
                    cmd_routing(chat_id, message_id)
                else:
                    send(chat_id, f'❌ {r.get("error", "?")}')
        else:
            log.info(f'unknown callback: {data}')
    except Exception:
        log.error(f'callback {data} failed:\n{traceback.format_exc()}')
        send(chat_id, '❌ Внутренняя ошибка, см. journalctl -u vpn-bot')


def handle_update(upd: Dict[str, Any]):
    if 'message' in upd:
        msg = upd['message']
        user = msg.get('from', {})
        chat_id = msg.get('chat', {}).get('id')
        text = msg.get('text', '')
        user_id = user.get('id')
        if not is_owner(user_id):
            log.warning(f'rejected user {user_id} (@{user.get("username")})')
            if chat_id:
                send(chat_id, '⛔ Доступ запрещён')
            return
        if text.startswith('/'):
            handle_command(chat_id, text)
        else:
            send(chat_id, 'Команда должна начинаться с /. См. /help')
    elif 'callback_query' in upd:
        cq = upd['callback_query']
        user_id = cq.get('from', {}).get('id')
        if not is_owner(user_id):
            answer_cb(cq['id'], '⛔ Доступ запрещён', show_alert=True)
            return
        handle_callback(cq)


def main():
    log.info(f'VPN bot starting. admin={ADMIN_ID}, panel={PANEL_URL}')
    r = SESSION.get(f'{API}/getUpdates', params={'timeout': 0, 'offset': -1}, timeout=10)
    try:
        last = r.json().get('result', [])
        offset = (last[-1]['update_id'] + 1) if last else 0
    except Exception:
        offset = 0
    log.info(f'starting offset={offset}')

    while True:
        try:
            r = SESSION.get(
                f'{API}/getUpdates',
                params={'offset': offset, 'timeout': 30,
                        'allowed_updates': '["message","callback_query"]'},
                timeout=40,
            )
            data = r.json()
            if not data.get('ok'):
                log.warning(f'getUpdates: {data}')
                time.sleep(5)
                continue
            for upd in data.get('result', []):
                offset = upd['update_id'] + 1
                try:
                    handle_update(upd)
                except Exception:
                    log.error(f'handle_update:\n{traceback.format_exc()}')
        except requests.exceptions.ReadTimeout:
            continue
        except Exception:
            log.error(f'main loop:\n{traceback.format_exc()}')
            time.sleep(3)


if __name__ == '__main__':
    main()
