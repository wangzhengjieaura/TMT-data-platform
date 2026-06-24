const LOGIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>登录 · 新兴产业关键指标观测平台</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;}
body{background:#0f1117;color:#e2e8f0;font-family:'PingFang SC','Microsoft YaHei',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;}
.card{background:#1a1d2e;border:1px solid #2e3250;border-radius:12px;padding:40px;width:360px;}
.logo{font-size:11px;color:#6366f1;letter-spacing:2px;margin-bottom:16px;}
h1{font-size:17px;font-weight:700;margin-bottom:6px;}
.sub{font-size:12px;color:#64748b;margin-bottom:32px;}
label{display:block;font-size:12px;color:#94a3b8;margin-bottom:6px;}
input{width:100%;background:#0f1117;border:1px solid #2e3250;border-radius:6px;color:#e2e8f0;font-size:14px;padding:10px 12px;margin-bottom:18px;outline:none;transition:border-color .2s;}
input:focus{border-color:#6366f1;}
button{width:100%;background:#6366f1;border:none;border-radius:6px;color:#fff;font-size:14px;font-weight:600;padding:12px;cursor:pointer;transition:background .2s;}
button:hover{background:#818cf8;}
button:disabled{background:#3730a3;cursor:not-allowed;}
.err{color:#ef4444;font-size:12px;margin-top:14px;text-align:center;display:none;}
</style>
</head>
<body>
<div class="card">
  <div class="logo">GWSC RESEARCH</div>
  <h1>新兴产业关键指标观测平台</h1>
  <p class="sub">长城证券研究所 · 请登录后访问</p>
  <label>账号</label>
  <input type="text" id="u" placeholder="请输入账号" autocomplete="username">
  <label>密码</label>
  <input type="password" id="p" placeholder="请输入密码" autocomplete="current-password">
  <button id="btn" onclick="login()">登 录</button>
  <p class="err" id="err">账号或密码错误，请重试</p>
</div>
<script>
async function login() {
  const u = document.getElementById('u').value.trim();
  const p = document.getElementById('p').value;
  const btn = document.getElementById('btn');
  const err = document.getElementById('err');
  if (!u || !p) return;
  btn.disabled = true;
  btn.textContent = '验证中...';
  err.style.display = 'none';
  const res = await fetch('/api/login', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({u, p})
  });
  if (res.ok) {
    location.reload();
  } else {
    err.style.display = 'block';
    btn.disabled = false;
    btn.textContent = '登 录';
  }
}
document.addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
</script>
</body>
</html>`;

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);

  // 登录接口
  if (url.pathname === '/api/login' && request.method === 'POST') {
    try {
      const { u, p } = await request.json();
      if (!u || !p) return new Response('Bad Request', { status: 400 });
      const stored = await env.CREDENTIALS.get(u);
      if (stored && stored === p) {
        const token = generateToken();
        await env.SESSIONS.put(token, u, { expirationTtl: 604800 }); // 7天
        return new Response(JSON.stringify({ ok: true }), {
          headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': `_s=${token}; HttpOnly; Secure; Path=/; Max-Age=604800; SameSite=Strict`
          }
        });
      }
      return new Response('Unauthorized', { status: 401 });
    } catch {
      return new Response('Bad Request', { status: 400 });
    }
  }

  // 登出接口
  if (url.pathname === '/api/logout') {
    const token = getCookie(request, '_s');
    if (token) await env.SESSIONS.delete(token);
    return new Response(null, {
      status: 302,
      headers: {
        'Location': '/',
        'Set-Cookie': '_s=; HttpOnly; Secure; Path=/; Max-Age=0'
      }
    });
  }

  // 验证会话
  const token = getCookie(request, '_s');
  if (token) {
    const user = await env.SESSIONS.get(token);
    if (user) return next();
  }

  // 未登录，返回登录页
  return new Response(LOGIN_HTML, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function getCookie(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  const m = cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return m ? m[1] : null;
}

function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('');
}
