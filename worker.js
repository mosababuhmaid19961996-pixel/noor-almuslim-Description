const COOKIE = 'noor_vid';
const ADMIN_COOKIE = 'noor_admin_session';

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
  });
}

function newId() {
  return crypto.randomUUID();
}

function cookieValue(request, name) {
  const raw = request.headers.get('Cookie') || '';
  const part = raw.split(';').map(x => x.trim()).find(x => x.startsWith(name + '='));
  return part ? decodeURIComponent(part.slice(name.length + 1)) : null;
}

function isHtmlNavigation(request, pathname) {
  const accept = request.headers.get('Accept') || '';
  if (pathname.startsWith('/api/') || pathname.startsWith('/admin')) return false;
  if (/\.(css|js|png|jpg|jpeg|webp|svg|ico|gif|woff2?|ttf|mp3|mp4|pdf|zip)$/i.test(pathname)) return false;
  return request.method === 'GET' && accept.includes('text/html');
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), {name:'HMAC', hash:'SHA-256'}, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(value));
  return value + '.' + b64url(new Uint8Array(sig));
}

async function verify(token, secret) {
  if (!token || !secret) return false;
  const i = token.lastIndexOf('.');
  if (i < 1) return false;
  const value = token.slice(0, i), sig = token.slice(i + 1);
  const expected = await sign(value, secret);
  return expected.slice(expected.lastIndexOf('.') + 1) === sig;
}

function b64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

function setCookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Max-Age=${maxAge}; Path=/; HttpOnly; Secure; SameSite=Lax`;
}

async function requireAdmin(request, env) {
  const token = cookieValue(request, ADMIN_COOKIE);
  return verify(token, env.ADMIN_SESSION_SECRET);
}

async function trackVisit(request, env, url) {
  if (!env.DB || !isHtmlNavigation(request, url.pathname)) return null;
  const now = new Date();
  const iso = now.toISOString();
  const day = iso.slice(0,10);
  let vid = cookieValue(request, COOKIE);
  const fresh = !vid;
  if (!vid) vid = newId();
  await env.DB.prepare(`INSERT INTO visitors(visitor_id, first_seen, last_seen) VALUES(?,?,?) ON CONFLICT(visitor_id) DO UPDATE SET last_seen=excluded.last_seen`).bind(vid, iso, iso).run();
  await env.DB.prepare(`INSERT OR IGNORE INTO daily_visitors(day, visitor_id) VALUES(?,?)`).bind(day, vid).run();
  await env.DB.prepare(`INSERT INTO pageviews(visitor_id,path,viewed_at) VALUES(?,?,?)`).bind(vid, url.pathname, iso).run();
  return fresh ? vid : null;
}

async function api(request, env, url) {
  if (!env.DB) return json({error:'D1 database is not configured yet.'}, 503);
  if (url.pathname === '/api/login' && request.method === 'POST') {
    const body = await request.json().catch(() => ({}));
    if (!env.ADMIN_PASSWORD || !env.ADMIN_SESSION_SECRET) return json({error:'Admin secrets are not configured.'},503);
    if (body.password !== env.ADMIN_PASSWORD) return json({error:'كلمة المرور غير صحيحة.'},401);
    const token = await sign('admin.' + Date.now(), env.ADMIN_SESSION_SECRET);
    return new Response(JSON.stringify({ok:true}), {headers:{'content-type':'application/json; charset=utf-8','Set-Cookie':setCookie(ADMIN_COOKIE,token,60*60*12),'cache-control':'no-store'}});
  }
  if (url.pathname === '/api/logout' && request.method === 'POST') {
    return new Response(JSON.stringify({ok:true}), {headers:{'content-type':'application/json; charset=utf-8','Set-Cookie':`${ADMIN_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`,'cache-control':'no-store'}});
  }
  if (url.pathname === '/api/suggestions' && request.method === 'POST') {
    let vid = cookieValue(request, COOKIE);
    if (!vid) vid = newId();
    const body = await request.json().catch(() => ({}));
    const message = String(body.message || '').trim().slice(0,4000);
    const name = String(body.name || 'زائر').trim().slice(0,120);
    if (!message) return json({error:'اكتب الرسالة أولًا.'},400);
    const now = new Date().toISOString();
    await env.DB.prepare(`INSERT INTO messages(visitor_id,role,name,body,created_at) VALUES(?,?,?,?,?)`).bind(vid,'visitor',name,message,now).run();
    const headers = {'content-type':'application/json; charset=utf-8','cache-control':'no-store'};
    if (!cookieValue(request, COOKIE)) headers['Set-Cookie'] = setCookie(COOKIE,vid,60*60*24*365*2);
    return new Response(JSON.stringify({ok:true}),{headers});
  }
  if (url.pathname === '/api/messages' && request.method === 'GET') {
    let vid = cookieValue(request, COOKIE);
    if (!vid) return json({messages:[]});
    const rows = await env.DB.prepare(`SELECT id,role,name,body,created_at FROM messages WHERE visitor_id=? ORDER BY id ASC LIMIT 200`).bind(vid).all();
    return json({messages:rows.results || []});
  }
  if (url.pathname === '/api/admin/stats' && request.method === 'GET') {
    if (!(await requireAdmin(request, env))) return json({error:'غير مصرح.'},401);
    const now = new Date();
    const day = now.toISOString().slice(0,10);
    const month = day.slice(0,7);
    const [total, today, monthCount, views, unread] = await Promise.all([
      env.DB.prepare('SELECT COUNT(*) AS n FROM visitors').first(),
      env.DB.prepare('SELECT COUNT(*) AS n FROM daily_visitors WHERE day=?').bind(day).first(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM daily_visitors WHERE day LIKE ?").bind(month+'%').first(),
      env.DB.prepare('SELECT COUNT(*) AS n FROM pageviews').first(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM messages WHERE role='visitor'").first()
    ]);
    return json({totalVisitors:total.n||0,todayVisitors:today.n||0,monthVisitors:monthCount.n||0,pageViews:views.n||0,messages:unread.n||0});
  }
  if (url.pathname === '/api/admin/messages' && request.method === 'GET') {
    if (!(await requireAdmin(request, env))) return json({error:'غير مصرح.'},401);
    const rows = await env.DB.prepare('SELECT id,visitor_id,role,name,body,created_at FROM messages ORDER BY id DESC LIMIT 300').all();
    return json({messages:rows.results || []});
  }
  if (url.pathname === '/api/admin/reply' && request.method === 'POST') {
    if (!(await requireAdmin(request, env))) return json({error:'غير مصرح.'},401);
    const body = await request.json().catch(() => ({}));
    const vid = String(body.visitor_id || '');
    const message = String(body.message || '').trim().slice(0,4000);
    if (!vid || !message) return json({error:'بيانات ناقصة.'},400);
    await env.DB.prepare(`INSERT INTO messages(visitor_id,role,name,body,created_at) VALUES(?,?,?,?,?)`).bind(vid,'admin','مسؤول المجموعة',message,new Date().toISOString()).run();
    return json({ok:true});
  }
  return json({error:'Not found'},404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) return api(request, env, url);
    if (url.pathname === '/admin' || url.pathname === '/admin/' || url.pathname === '/admin/index.html') {
      if (await requireAdmin(request, env)) return env.ASSETS.fetch(new Request(new URL('/admin-dashboard.html', request.url), request));
      return env.ASSETS.fetch(new Request(new URL('/admin-login.html', request.url), request));
    }
    let newVisitorCookie = null;
    try { newVisitorCookie = await trackVisit(request, env, url); } catch (_) {}
    const response = await env.ASSETS.fetch(request);
    if (newVisitorCookie) {
      const headers = new Headers(response.headers);
      headers.append('Set-Cookie', setCookie(COOKIE,newVisitorCookie,60*60*24*365*2));
      return new Response(response.body,{status:response.status,statusText:response.statusText,headers});
    }
    return response;
  }
};
