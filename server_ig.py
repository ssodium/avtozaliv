#!/usr/bin/env python3
"""
IGTools — Instagram Multi-Account Manager
pip install flask instagrapi pillow
python server.py
"""

from flask import Flask, request, jsonify, send_from_directory
import json, os, threading, time, uuid
from datetime import datetime

app = Flask(__name__, static_folder='.')
DATA_FILE = 'igtools_data.json'
UPLOAD_DIR = 'uploads'
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ── DATA ──────────────────────────────────────────────────────────────────────
def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE) as f: return json.load(f)
        except: pass
    return {'accounts': [], 'tasks': []}

def save_data(d):
    with open(DATA_FILE, 'w') as f: json.dump(d, f, indent=2, default=str)

D = load_data()
clients = {}  # acc_id -> InstagrapiClient
task_lock = threading.Lock()

# ── INSTAGRAM CLIENT ──────────────────────────────────────────────────────────

def normalize_proxy(proxy_str):
    """
    Convert various proxy formats to standard URL format.
    Handles:
      socks5://host:port:user:pass  -> socks5://user:pass@host:port
      socks5://user:pass@host:port  -> unchanged
      http://host:port:user:pass    -> http://user:pass@host:port
      host:port:user:pass           -> http://user:pass@host:port
      host:port                     -> http://host:port
    """
    if not proxy_str or not proxy_str.strip():
        return proxy_str
    p = proxy_str.strip()
    
    # Already has @  = standard format, return as-is
    if '@' in p:
        return p
    
    # Detect scheme
    scheme = 'http'
    if p.startswith('socks5://'):
        scheme = 'socks5'
        p = p[9:]
    elif p.startswith('socks4://'):
        scheme = 'socks4'
        p = p[9:]
    elif p.startswith('http://'):
        scheme = 'http'
        p = p[7:]
    elif p.startswith('https://'):
        scheme = 'https'
        p = p[8:]
    
    parts = p.split(':')
    
    if len(parts) == 4:
        # host:port:user:pass
        host, port, user, passwd = parts
        return f'{scheme}://{user}:{passwd}@{host}:{port}'
    elif len(parts) == 2:
        # host:port
        return f'{scheme}://{p}'
    else:
        return proxy_str  # Can't parse, return original

def get_totp_code(secret):
    """Generate TOTP code from secret key using pyotp"""
    try:
        import pyotp
        secret_clean = secret.replace(' ','').upper()
        # Pad if needed
        pad = (8 - len(secret_clean) % 8) % 8
        totp = pyotp.TOTP(secret_clean + '=' * pad)
        return totp.now()
    except Exception as e:
        return None

def do_instagram_login(cl, username, password, totp_secret=None, manual_code=None):
    """
    Try to login. Handle 2FA automatically.
    Returns (True, None) on success or (False, error_msg) on failure.
    """
    # Step 1: attempt plain login
    try:
        cl.login(username, password)
        return True, None
    except Exception as e:
        err = str(e)
        etype = type(e).__name__

        # 2FA required
        if 'TwoFactorRequired' in etype or 'two_factor' in err.lower():
            code = manual_code or (get_totp_code(totp_secret) if totp_secret else None)
            if not code:
                return False, '2FA_REQUIRED'

            # Create fresh client for 2FA attempt (avoids state issues)
            try:
                cl.login(username, password, verification_code=code)
                return True, None
            except Exception as e2:
                return False, f'2FA ошибка: {str(e2)[:200]}'

        # Email/phone challenge
        if 'ChallengeRequired' in etype or 'challenge_required' in err.lower():
            return False, 'CHALLENGE_REQUIRED'

        # Bad password
        if 'BadPassword' in etype or 'password' in err.lower():
            return False, 'Неверный пароль'

        return False, err[:200]

def get_client(acc_id, manual_2fa_code=None):
    """Get or create authenticated Instagram client for account"""
    # Return cached client unless manual code provided
    if acc_id in clients and not manual_2fa_code:
        return clients[acc_id], None

    acc = next((a for a in D['accounts'] if a['id'] == acc_id), None)
    if not acc: return None, 'Account not found'

    try:
        from instagrapi import Client
        cl = Client()
        # Set request timeout to avoid hanging
        cl.request_timeout = 30

        if acc.get('proxy'):
            cl.set_proxy(normalize_proxy(acc['proxy']))

        # Restore session if available
        if acc.get('session') and not manual_2fa_code:
            try:
                cl.set_settings(acc['session'])
            except Exception:
                pass

        ok, err = do_instagram_login(
            cl,
            acc['username'],
            acc['password'],
            totp_secret=acc.get('totp_secret'),
            manual_code=manual_2fa_code
        )

        if not ok:
            if err == '2FA_REQUIRED':
                # Save partial client state so manual code can reuse it
                clients[acc_id + '_2fa'] = cl
                update_acc_status(acc_id, 'need_2fa')
                return None, '2FA_REQUIRED: Аккаунт защищён двухфакторной аутентификацией. Нажми 🔒 и введи код.'
            if err == 'CHALLENGE_REQUIRED':
                # Try to trigger challenge send
                try:
                    cl.challenge_resolve(cl.last_json)
                except Exception:
                    pass
                clients[acc_id + '_pending'] = cl
                update_acc_status(acc_id, 'challenge')
                return None, 'Instagram требует подтверждение по email/SMS. Нажми кнопку ✉️ на карточке аккаунта.'

            return None, err

        # Success - save session
        acc['session'] = cl.get_settings()
        save_data(D)
        clients[acc_id] = cl
        return cl, None

    except Exception as e:
        return None, str(e)[:200]

def update_acc_status(acc_id, status, error=None):
    acc = next((a for a in D['accounts'] if a['id'] == acc_id), None)
    if acc:
        acc['status'] = status
        acc['last_check'] = datetime.now().isoformat()
        if error: acc['last_error'] = error
        save_data(D)

# ── ROUTES — ACCOUNTS ─────────────────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('.', 'igtools.html')

@app.route('/api/accounts', methods=['GET'])
def get_accounts():
    safe = []
    for a in D['accounts']:
        safe.append({k: v for k, v in a.items() if k not in ('password', 'session', 'totp_secret')})
    return jsonify(safe)

@app.route('/api/accounts', methods=['POST'])
def add_account():
    data = request.json
    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'username and password required'}), 400
    # Check duplicate
    if any(a['username'] == data['username'] for a in D['accounts']):
        return jsonify({'error': 'Account already exists'}), 400
    acc = {
        'id': str(uuid.uuid4())[:8],
        'username': data['username'],
        'password': data['password'],
        'proxy': data.get('proxy', ''),
        'totp_secret': data.get('totp_secret', '').replace(' ', ''),
        'status': 'pending',
        'added': datetime.now().isoformat(),
        'last_check': None,
        'last_error': None,
        'session': None,
        'posts_today': 0,
        'stories_today': 0,
    }
    D['accounts'].append(acc)
    save_data(D)
    # Try login in background
    threading.Thread(target=check_account_bg, args=(acc['id'],), daemon=True).start()
    return jsonify({'ok': True, 'id': acc['id']})

@app.route('/api/accounts/<acc_id>', methods=['DELETE'])
def delete_account(acc_id):
    D['accounts'] = [a for a in D['accounts'] if a['id'] != acc_id]
    clients.pop(acc_id, None)
    save_data(D)
    return jsonify({'ok': True})


@app.route('/api/accounts/<acc_id>', methods=['PATCH'])
def edit_account(acc_id):
    acc = next((a for a in D['accounts'] if a['id'] == acc_id), None)
    if not acc: return jsonify({'error': 'not found'}), 404
    data = request.json
    if 'proxy' in data and data['proxy'] != acc.get('proxy'):
        acc['proxy'] = data['proxy']
        clients.pop(acc_id, None)
        acc['session'] = None
    if 'totp_secret' in data and data['totp_secret']:
        acc['totp_secret'] = data['totp_secret'].replace(' ','')
        clients.pop(acc_id, None)
    if 'password' in data and data['password']:
        acc['password'] = data['password']
        clients.pop(acc_id, None)
        acc['session'] = None
    if 'notes' in data:
        acc['notes'] = data['notes']
    save_data(D)
    return jsonify({'ok': True})

@app.route('/api/accounts/<acc_id>/check', methods=['POST'])
def check_account(acc_id):
    threading.Thread(target=check_account_bg, args=(acc_id,), daemon=True).start()
    return jsonify({'ok': True, 'message': 'Checking in background'})

def check_account_bg(acc_id):
    update_acc_status(acc_id, 'connecting')
    try:
        cl, err = get_client(acc_id)
        if err:
            # Don't overwrite special statuses set by get_client
            acc = next((a for a in D['accounts'] if a['id'] == acc_id), None)
            if acc and acc.get('status') in ('need_2fa', 'challenge'):
                return  # Keep the special status
            update_acc_status(acc_id, 'error', err)
            return
        try:
            info = cl.account_info()
            acc = next((a for a in D['accounts'] if a['id'] == acc_id), None)
            if acc:
                def ga(obj, *keys, default=0):
                    for k in keys:
                        v = getattr(obj, k, None)
                        if v is not None: return v
                    return default
                acc['full_name'] = ga(info, 'full_name', default='')
                acc['followers'] = ga(info, 'follower_count', 'media_count')
                acc['following'] = ga(info, 'following_count', 'usertags_count')
                acc['posts'] = ga(info, 'media_count', 'feed_items_count')
                acc['pk'] = str(ga(info, 'pk', default=''))
                save_data(D)
            update_acc_status(acc_id, 'ok')
        except Exception as e:
            update_acc_status(acc_id, 'error', str(e)[:200])
    except Exception as e:
        update_acc_status(acc_id, 'error', str(e)[:200])






@app.route('/api/proxy/test', methods=['POST'])
def test_proxy():
    proxy = request.json.get('proxy', '')
    if not proxy: return jsonify({'error': 'no proxy'}), 400
    normalized = normalize_proxy(proxy)
    try:
        import requests as req
        proxies = {'http': normalized, 'https': normalized}
        r = req.get('https://api.ipify.org?format=json', proxies=proxies, timeout=10)
        ip_data = r.json()
        return jsonify({'ok': True, 'ip': ip_data.get('ip'), 'normalized': normalized})
    except Exception as e:
        return jsonify({'error': str(e)[:200], 'normalized': normalized}), 400

@app.route('/api/accounts/add_by_cookies', methods=['POST'])
def add_by_cookies():
    """Add account using only cookies - username extracted from session"""
    cookies = request.json.get('cookies')
    proxy = request.json.get('proxy', '')
    if not cookies: return jsonify({'error': 'cookies required'}), 400
    try:
        from instagrapi import Client
        cl = Client()
        cl.request_timeout = 30
        if proxy: cl.set_proxy(normalize_proxy(proxy))

        if isinstance(cookies, str):
            import json as _json
            cookies = _json.loads(cookies)
        if isinstance(cookies, list):
            cookies = {item['name']: item['value'] for item in cookies if 'name' in item}

        session_id = cookies.get('sessionid') or cookies.get('sessionId') or cookies.get('session_id')
        if not session_id:
            return jsonify({'error': 'sessionid не найден в куки'}), 400

        # Login by sessionid
        try:
            cl.login_by_sessionid(session_id)
        except Exception:
            cl.set_settings({'cookies': cookies})

        # Get account info to extract username
        info = cl.account_info()
        def ga(obj, *keys, default=''):
            for k in keys:
                v = getattr(obj, k, None)
                if v is not None: return v
            return default

        username = ga(info, 'username', default='')
        if not username:
            return jsonify({'error': 'Не удалось получить username из сессии'}), 400

        # Check if already exists
        if any(a['username'] == username for a in D['accounts']):
            return jsonify({'error': f'Аккаунт @{username} уже добавлен'}), 400

        acc_id = str(uuid.uuid4())[:8]
        acc = {
            'id': acc_id,
            'username': username,
            'password': '',
            'proxy': proxy,
            'totp_secret': '',
            'status': 'ok',
            'added': datetime.now().isoformat(),
            'last_check': datetime.now().isoformat(),
            'last_error': None,
            'session': cl.get_settings(),
            'notes': 'Вход по куки',
            'posts_today': 0,
            'stories_today': 0,
            'full_name': ga(info, 'full_name', default=''),
            'followers': ga(info, 'follower_count', 'media_count', default=0),
            'following': ga(info, 'following_count', default=0),
            'posts': ga(info, 'media_count', default=0),
            'pk': str(ga(info, 'pk', default='')),
        }
        D['accounts'].append(acc)
        clients[acc_id] = cl
        save_data(D)
        return jsonify({'ok': True, 'username': username, 'id': acc_id})
    except Exception as e:
        return jsonify({'error': str(e)[:300]}), 400

@app.route('/api/accounts/<acc_id>/login_cookies', methods=['POST'])
def login_with_cookies(acc_id):
    """Login using cookies JSON"""
    cookies = request.json.get('cookies')
    if not cookies: return jsonify({'error': 'cookies required'}), 400
    acc = next((a for a in D['accounts'] if a['id'] == acc_id), None)
    if not acc: return jsonify({'error': 'not found'}), 404
    try:
        from instagrapi import Client
        cl = Client()
        if acc.get('proxy'): cl.set_proxy(normalize_proxy(acc['proxy']))
        if isinstance(cookies, str):
            import json as _json
            cookies = _json.loads(cookies)
        # Handle array format from EditThisCookie
        if isinstance(cookies, list):
            cookies = {item['name']: item['value'] for item in cookies if 'name' in item}
        # Extract sessionid
        session_id = cookies.get('sessionid') or cookies.get('sessionId') or cookies.get('session_id')
        login_ok = False
        last_err = None
        # Method 1: login_by_sessionid with username
        if session_id:
            try:
                cl.login_by_sessionid(session_id, username=acc['username'])
                login_ok = True
            except Exception as e1:
                last_err = str(e1)
                try:
                    cl.login_by_sessionid(session_id)
                    login_ok = True
                except Exception as e2:
                    last_err = str(e2)
        # Method 2: set full cookie settings
        if not login_ok:
            try:
                cl2 = Client()
                if acc.get('proxy'): cl2.set_proxy(acc['proxy'])
                cl2.set_settings({'cookies': cookies})
                cl = cl2
                login_ok = True
            except Exception as e3:
                last_err = str(e3)
        if not login_ok:
            return jsonify({'error': f'Ошибка входа по куки: {last_err}'}), 400
        # Verify session works
        info = cl.account_info()
        acc['session'] = cl.get_settings()
        def ga(obj, *keys, default=0):
            for k in keys:
                v = getattr(obj, k, None)
                if v is not None: return v
            return default
        acc['full_name'] = ga(info, 'full_name', default='')
        acc['followers'] = ga(info, 'follower_count', 'media_count')
        acc['following'] = ga(info, 'following_count', 'usertags_count')
        acc['posts'] = ga(info, 'media_count', 'feed_items_count')
        acc['pk'] = str(ga(info, 'pk', default=''))
        save_data(D)
        clients[acc_id] = cl
        update_acc_status(acc_id, 'ok')
        return jsonify({'ok': True, 'username': acc['username']})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/accounts/<acc_id>/login_2fa', methods=['POST'])
def login_with_2fa(acc_id):
    """Login with manually entered 2FA code"""
    code = request.json.get('code', '').strip()
    if not code: return jsonify({'error': 'code required'}), 400
    # Clear cached client so get_client creates fresh one with manual code
    clients.pop(acc_id, None)
    cl, err = get_client(acc_id, manual_2fa_code=code)
    if err and err != 'ok':
        return jsonify({'error': err}), 400
    update_acc_status(acc_id, 'ok')
    return jsonify({'ok': True})

@app.route('/api/accounts/<acc_id>/challenge', methods=['POST'])
def resolve_challenge(acc_id):
    """Submit email/SMS verification code for Instagram challenge"""
    code = request.json.get('code', '').strip()
    if not code: return jsonify({'error': 'code required'}), 400
    cl = clients.get(acc_id + '_pending')
    if not cl:
        return jsonify({'error': 'No pending challenge for this account'}), 400
    try:
        cl.challenge_resolve(cl.last_json)
        # Try sending the code
        cl.challenge_resolve_simple(code)
        acc = next((a for a in D['accounts'] if a['id'] == acc_id), None)
        if acc:
            acc['session'] = cl.get_settings()
            save_data(D)
        clients[acc_id] = cl
        clients.pop(acc_id + '_pending', None)
        update_acc_status(acc_id, 'ok')
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/accounts/<acc_id>/challenge/send', methods=['POST'])
def send_challenge(acc_id):
    """Request Instagram to send email/SMS code"""
    cl = clients.get(acc_id + '_pending')
    if not cl: return jsonify({'error': 'No pending challenge'}), 400
    try:
        cl.challenge_resolve(cl.last_json)
        return jsonify({'ok': True, 'message': 'Code sent to email/phone'})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/accounts/<acc_id>/proxy', methods=['POST'])
def set_proxy(acc_id):
    proxy = request.json.get('proxy', '')
    acc = next((a for a in D['accounts'] if a['id'] == acc_id), None)
    if not acc: return jsonify({'error': 'not found'}), 404
    acc['proxy'] = proxy
    # Reset client so it reconnects with new proxy
    clients.pop(acc_id, None)
    acc['session'] = None
    save_data(D)
    return jsonify({'ok': True})

# ── ROUTES — POSTING ──────────────────────────────────────────────────────────
@app.route('/api/upload', methods=['POST'])
def upload_media():
    if 'file' not in request.files:
        return jsonify({'error': 'no file'}), 400
    f = request.files['file']
    fname = str(uuid.uuid4())[:8] + '_' + f.filename
    path = os.path.join(UPLOAD_DIR, fname)
    f.save(path)
    return jsonify({'ok': True, 'path': path, 'name': f.filename})

@app.route('/api/post', methods=['POST'])
def create_post():
    data = request.json
    acc_ids = data.get('accounts', [])
    media_path = data.get('media_path', '')
    caption = data.get('caption', '')
    post_type = data.get('type', 'photo')  # photo, video, story, reel
    delay = int(data.get('delay', 0))  # seconds between posts
    notes = data.get('notes', '')

    if not acc_ids: return jsonify({'error': 'no accounts selected'}), 400
    if not media_path: return jsonify({'error': 'no media'}), 400
    if not os.path.exists(media_path): return jsonify({'error': 'media file not found'}), 400

    task_id = str(uuid.uuid4())[:8]
    task = {
        'id': task_id,
        'type': post_type,
        'accounts': acc_ids,
        'media': media_path,
        'caption': caption,
        'delay': delay,
        'notes': notes,
        'status': 'queued',
        'progress': 0,
        'current_acc': None,
        'results': {},
        'created': datetime.now().isoformat(),
        'started': None,
        'finished': None,
    }
    with task_lock:
        D['tasks'].append(task)
        save_data(D)

    threading.Thread(target=run_post_task, args=(task_id,), daemon=True).start()
    return jsonify({'ok': True, 'task_id': task_id})

def run_post_task(task_id):
    task = next((t for t in D['tasks'] if t['id'] == task_id), None)
    if not task: return
    task['status'] = 'running'
    task['started'] = datetime.now().isoformat()
    task['progress'] = 0
    task['current_acc'] = None
    save_data(D)

    total = len(task['accounts'])
    for i, acc_id in enumerate(task['accounts']):
        task['progress'] = i
        task['current_acc'] = acc_id
        save_data(D)

        if i > 0 and task['delay'] > 0:
            time.sleep(task['delay'])

        try:
            cl, err = get_client(acc_id)
            if err:
                task['results'][acc_id] = {'status': 'error', 'error': err}
                save_data(D)
                continue

            post_type = task['type']
            path = task['media']
            caption = task['caption']

            if not os.path.exists(path):
                task['results'][acc_id] = {'status': 'error', 'error': f'Файл не найден: {path}'}
                save_data(D)
                continue

            result = None
            if post_type == 'photo':
                r = cl.photo_upload(path, caption)
                result = {'status': 'ok', 'media_id': str(r.pk), 'url': f'https://instagram.com/p/{r.code}'}
            elif post_type == 'video':
                thumb_path_v = path + '_vthumb.jpg'
                try:
                    import subprocess
                    subprocess.run(['ffmpeg','-i',path,'-ss','00:00:01','-vframes','1','-q:v','2',thumb_path_v,'-y'], capture_output=True, timeout=30)
                except Exception:
                    pass
                if os.path.exists(thumb_path_v):
                    r = cl.video_upload(path, caption, thumbnail=thumb_path_v)
                    try: os.remove(thumb_path_v)
                    except: pass
                else:
                    r = cl.video_upload(path, caption)
                result = {'status': 'ok', 'media_id': str(r.pk), 'url': f'https://instagram.com/p/{r.code}'}
            elif post_type == 'story_photo':
                r = cl.photo_upload_to_story(path)
                result = {'status': 'ok', 'media_id': str(r.pk)}
            elif post_type == 'story_video':
                r = cl.video_upload_to_story(path)
                result = {'status': 'ok', 'media_id': str(r.pk)}
            elif post_type == 'reel':
                # Generate thumbnail for reel
                thumb_path = path + '_thumb.jpg'
                thumb_generated = False
                # Try ffmpeg first
                try:
                    import subprocess
                    ret = subprocess.run(
                        ['ffmpeg', '-i', path, '-ss', '00:00:01', '-vframes', '1', '-q:v', '2', thumb_path, '-y'],
                        capture_output=True, timeout=30
                    )
                    if ret.returncode == 0 and os.path.exists(thumb_path):
                        thumb_generated = True
                except Exception:
                    pass
                # Fallback: use Pillow to create black thumbnail
                if not thumb_generated:
                    try:
                        from PIL import Image
                        img = Image.new('RGB', (1080, 1920), color=(0, 0, 0))
                        img.save(thumb_path, 'JPEG')
                        thumb_generated = True
                    except Exception:
                        pass
                if thumb_generated:
                    r = cl.clip_upload(path, caption, thumbnail=thumb_path)
                    try: os.remove(thumb_path)
                    except: pass
                else:
                    r = cl.clip_upload(path, caption)
                result = {'status': 'ok', 'media_id': str(r.pk), 'url': f'https://instagram.com/reel/{r.code}'}
            else:
                result = {'status': 'error', 'error': f'Неизвестный тип: {post_type}'}

            task['results'][acc_id] = result
            acc = next((a for a in D['accounts'] if a['id'] == acc_id), None)
            if acc:
                if 'story' in post_type: acc['stories_today'] = acc.get('stories_today', 0) + 1
                else: acc['posts_today'] = acc.get('posts_today', 0) + 1
        except Exception as e:
            task['results'][acc_id] = {'status': 'error', 'error': str(e)[:300]}

        save_data(D)

    task['status'] = 'done'
    task['progress'] = total
    task['current_acc'] = None
    task['finished'] = datetime.now().isoformat()
    save_data(D)

@app.route('/api/tasks', methods=['GET'])
def get_tasks():
    return jsonify(list(reversed(D['tasks'][-50:])))

@app.route('/api/tasks/<task_id>', methods=['GET'])
def get_task(task_id):
    task = next((t for t in D['tasks'] if t['id'] == task_id), None)
    if not task: return jsonify({'error': 'not found'}), 404
    return jsonify(task)

@app.route('/api/tasks/<task_id>', methods=['DELETE'])
def delete_task(task_id):
    D['tasks'] = [t for t in D['tasks'] if t['id'] != task_id]
    save_data(D)
    return jsonify({'ok': True})

# ── START ─────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print('IGTools running on http://localhost:8081')
    app.run(host='0.0.0.0', port=8081, debug=False)
