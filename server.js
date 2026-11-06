require('dotenv').config();
const express = require('express'), multer = require('multer');
const path = require('path'), crypto = require('crypto');
const supabase = require('./supabase');

const PORT = process.env.PORT || 3000;
const ADMIN_PASS = process.env.ADMIN_PASS || 'change-me';
const SECRET = process.env.SESSION_SECRET || ADMIN_PASS;
const IS_PROD = process.env.NODE_ENV === 'production';
const IMG_BUCKET = 'product-images';
const RCPT_BUCKET = 'receipts';
const WEEK = 7 * 24 * 60 * 60 * 1000;

const id = () => crypto.randomBytes(6).toString('hex');
const wrap = fn => (q, s, next) => fn(q, s, next).catch(err => {
  console.error(err);
  s.status(500).json({ error: 'صار خطأ في السيرفر، حاول مرة ثانية' });
});

// ---- رفع الملفات (في الذاكرة ثم إلى Supabase Storage) ----
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (q, f, cb) => cb(null, /^image\//.test(f.mimetype))
});

async function putFile(bucket, file) {
  let ext = path.extname(file.originalname).toLowerCase();
  if (!/^\.(jpe?g|png|webp|gif|heic)$/.test(ext)) ext = '.jpg';
  const name = id() + ext;
  const { error } = await supabase.storage.from(bucket).upload(name, file.buffer, { contentType: file.mimetype });
  if (error) throw error;
  return name;
}
const removeFile = (bucket, name) => name ? supabase.storage.from(bucket).remove([name]).catch(() => {}) : null;

// ---- جلسات العملاء (موقّعة، تبقى بعد إعادة تشغيل السيرفر) ----
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
function makeToken(uid) {
  const p = uid + '.' + (Date.now() + WEEK);
  return p + '.' + sign(p);
}
function readToken(t) {
  if (!t) return null;
  const parts = String(t).split('.');
  if (parts.length !== 3) return null;
  const [uid, exp, sig] = parts;
  const expected = sign(uid + '.' + exp);
  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  if (Date.now() > Number(exp)) return null;
  return uid;
}
const cookieOpts = { httpOnly: true, sameSite: 'lax', secure: IS_PROD };
const hashPassword = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');

const admin = (q, s, next) =>
  q.get('x-admin') === ADMIN_PASS ? next() : s.status(401).json({ error: 'كلمة السر غير صحيحة' });

function customerAuth(q, s, next) {
  const uid = readToken(q.cookies?.customerSession);
  if (!uid) return s.status(401).json({ error: 'سجلي الدخول أولاً' });
  q.customerId = uid;
  next();
}

// ---- تحويل صفوف قاعدة البيانات لنفس شكل الواجهة ----
const toProduct = p => ({
  id: p.id, name: p.name, price: Number(p.price), desc: p.description || '',
  category: p.category || '', quantity: p.quantity, image: p.image || '', soldout: p.soldout
});
const toOrder = o => ({
  id: o.order_number, date: o.created_at, customerId: o.customer_id,
  name: o.customer_name || o.name, phone: o.phone, region: o.region, place: o.place,
  items: o.items || [], total: Number(o.total),
  receipt: `/api/orders/${o.order_number}/receipt`, status: o.status
});

async function adjustStock(pid, delta) {
  const { data: p } = await supabase.from('products').select('quantity').eq('id', pid).maybeSingle();
  if (!p) return;
  const qty = Math.max(0, Number(p.quantity) + delta);
  await supabase.from('products').update({ quantity: qty, soldout: qty === 0 }).eq('id', pid);
}

async function nextOrderNumber() {
  const { data } = await supabase.from('orders').select('order_number');
  const max = (data || []).reduce((m, o) => Math.max(m, Number(o.order_number) || 0), 0);
  return String(max + 1).padStart(2, '0');
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use((q, s, next) => {
  q.cookies = {};
  (q.headers.cookie || '').split(';').forEach(c => {
    const [name, ...v] = c.trim().split('=');
    if (name) { try { q.cookies[name] = decodeURIComponent(v.join('=')); } catch {} }
  });
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

// ================= حسابات العملاء =================
app.post('/api/register', wrap(async (q, s) => {
  const { name, phone, password } = q.body;
  if (!name || !phone || !password) return s.status(400).json({ error: 'عبّي جميع البيانات' });
  if (String(password).length < 8) return s.status(400).json({ error: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل' });

  const cleanPhone = String(phone).trim();
  const { data: exists } = await supabase.from('customers').select('id').eq('phone', cleanPhone).maybeSingle();
  if (exists) return s.status(409).json({ error: 'رقم الهاتف مسجل مسبقاً' });

  const salt = crypto.randomBytes(16).toString('hex');
  const user = { id: id(), name: String(name).trim(), phone: cleanPhone, salt, password_hash: hashPassword(String(password), salt) };
  const { error } = await supabase.from('customers').insert(user);
  if (error) throw error;

  s.cookie('customerSession', makeToken(user.id), { ...cookieOpts, maxAge: WEEK });
  s.json({ ok: true, user: { id: user.id, name: user.name, phone: user.phone } });
}));

app.post('/api/login', wrap(async (q, s) => {
  const { phone, password } = q.body;
  const bad = () => s.status(401).json({ error: 'رقم الهاتف أو كلمة المرور غير صحيحة' });
  if (!phone || !password) return bad();

  const { data: user } = await supabase.from('customers').select('*').eq('phone', String(phone).trim()).maybeSingle();
  if (!user) return bad();

  const hash = hashPassword(String(password), user.salt);
  const ok = hash.length === user.password_hash.length &&
    crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(user.password_hash, 'hex'));
  if (!ok) return bad();

  s.cookie('customerSession', makeToken(user.id), { ...cookieOpts, maxAge: WEEK });
  s.json({ ok: true, user: { id: user.id, name: user.name, phone: user.phone } });
}));

app.get('/api/me', customerAuth, wrap(async (q, s) => {
  const { data: u } = await supabase.from('customers').select('id,name,phone').eq('id', q.customerId).maybeSingle();
  if (!u) return s.sendStatus(404);
  s.json(u);
}));

app.post('/api/logout', (q, s) => {
  s.clearCookie('customerSession', cookieOpts);
  s.json({ ok: true });
});

app.get('/api/my-orders', customerAuth, wrap(async (q, s) => {
  const { data, error } = await supabase.from('orders').select('*').eq('customer_id', q.customerId).order('created_at', { ascending: false });
  if (error) throw error;
  s.json(data.map(toOrder));
}));

// ================= المنتجات =================
app.get('/api/products', wrap(async (q, s) => {
  const { data, error } = await supabase.from('products').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  s.json(data.map(toProduct));
}));

app.post('/api/products', admin, upload.single('image'), wrap(async (q, s) => {
  const { name, price, desc, category, quantity } = q.body;
  const stock = Number(quantity);
  if (!name || price === undefined || price === '' || !isFinite(+price))
    return s.status(400).json({ error: 'الاسم والسعر مطلوبين' });
  if (quantity === undefined || quantity === '' || !Number.isInteger(stock) || stock < 0)
    return s.status(400).json({ error: 'أدخلي كمية صحيحة' });

  let image = '';
  if (q.file) {
    const fname = await putFile(IMG_BUCKET, q.file);
    image = supabase.storage.from(IMG_BUCKET).getPublicUrl(fname).data.publicUrl;
  }
  const { error } = await supabase.from('products').insert({
    id: id(), name, price: +price, description: desc || '', category: category || '',
    quantity: stock, image, soldout: stock === 0
  });
  if (error) throw error;
  s.json({ ok: true });
}));

app.patch('/api/products/:id', admin, wrap(async (q, s) => {
  const upd = {};
  if (q.body.quantity !== undefined) {
    const stock = Number(q.body.quantity);
    if (!Number.isInteger(stock) || stock < 0) return s.status(400).json({ error: 'أدخل كمية صحيحة' });
    upd.quantity = stock;
    upd.soldout = stock === 0;
  }
  if (q.body.soldout !== undefined) upd.soldout = !!q.body.soldout;
  if (!Object.keys(upd).length) return s.status(400).json({ error: 'ما فيه شي للتعديل' });

  const { data, error } = await supabase.from('products').update(upd).eq('id', q.params.id).select('id');
  if (error) throw error;
  if (!data.length) return s.sendStatus(404);
  s.json({ ok: true });
}));

app.delete('/api/products/:id', admin, wrap(async (q, s) => {
  const { data: p } = await supabase.from('products').select('image').eq('id', q.params.id).maybeSingle();
  const { error } = await supabase.from('products').delete().eq('id', q.params.id);
  if (error) throw error;
  if (p?.image && p.image.includes('/' + IMG_BUCKET + '/')) await removeFile(IMG_BUCKET, p.image.split('/').pop());
  s.json({ ok: true });
}));

// ================= الطلبات =================
app.post('/api/orders', upload.single('receipt'), wrap(async (q, s) => {
  const { name, phone, region, place } = q.body;
  let items = [];
  try { items = JSON.parse(q.body.items); } catch {}
  if (!name || !phone || !region || !place || !q.file || !Array.isArray(items) || !items.length)
    return s.status(400).json({ error: 'عبّ كل البيانات وارفق صورة الإيصال' });

  const need = {};
  for (const it of items) {
    const qty = Number(it.qty);
    if (!it.id || !Number.isInteger(qty) || qty < 1)
      return s.status(400).json({ error: 'بيانات المنتج أو الكمية غير صحيحة' });
    need[it.id] = (need[it.id] || 0) + qty;
  }

  const { data: prods, error: pe } = await supabase.from('products').select('*').in('id', Object.keys(need));
  if (pe) throw pe;
  const byId = Object.fromEntries(prods.map(p => [p.id, p]));

  const lines = [];
  for (const it of items) {
    const p = byId[it.id];
    if (!p) return s.status(400).json({ error: 'منتج غير موجود' });
    lines.push({ productId: p.id, name: p.name, price: Number(p.price), qty: Number(it.qty), note: String(it.note || '').slice(0, 200) });
  }
  for (const [pid, qty] of Object.entries(need)) {
    const p = byId[pid];
    if (p.soldout || Number(p.quantity) < qty)
      return s.status(400).json({ error: `الكمية المتوفرة من ${p.name} غير كافية` });
  }

  const receiptName = await putFile(RCPT_BUCKET, q.file);

  // خصم الكمية بشرط ما تغيّرت (لو أحد طلب بنفس اللحظة نرجّع ونعتذر)
  const done = [];
  for (const [pid, qty] of Object.entries(need)) {
    const p = byId[pid];
    const left = Number(p.quantity) - qty;
    const { data, error } = await supabase.from('products')
      .update({ quantity: left, soldout: left === 0 })
      .eq('id', pid).eq('quantity', p.quantity).select('id');
    if (error || !data?.length) {
      for (const [dp, dq] of done) await adjustStock(dp, dq);
      await removeFile(RCPT_BUCKET, receiptName);
      return s.status(409).json({ error: 'تغيّرت الكمية المتوفرة، حدّث الصفحة وحاول مرة ثانية' });
    }
    done.push([pid, qty]);
  }

  const customerId = readToken(q.cookies?.customerSession);
  const orderNumber = await nextOrderNumber();
  const total = lines.reduce((a, l) => a + l.price * l.qty, 0);

  const { error: oe } = await supabase.from('orders').insert({
    id: id(), order_number: orderNumber, customer_id: customerId || null,
    customer_name: String(name).trim(), name: String(name).trim(),
    phone: String(phone).trim(), region: String(region).trim(), place: String(place).trim(),
    items: lines, total, receipt: receiptName, status: 'جديد'
  });
  if (oe) {
    for (const [dp, dq] of done) await adjustStock(dp, dq);
    await removeFile(RCPT_BUCKET, receiptName);
    throw oe;
  }
  s.json({ ok: true, id: orderNumber, total });
}));

app.get('/api/orders', admin, wrap(async (q, s) => {
  const { data, error } = await supabase.from('orders').select('*').order('created_at', { ascending: false });
  if (error) throw error;
  s.json(data.map(toOrder));
}));

app.get('/api/orders/:id/receipt', admin, wrap(async (q, s) => {
  const { data: o } = await supabase.from('orders').select('receipt').eq('order_number', String(q.params.id)).maybeSingle();
  if (!o?.receipt) return s.sendStatus(404);
  const { data, error } = await supabase.storage.from(RCPT_BUCKET).download(o.receipt);
  if (error || !data) return s.sendStatus(404);
  const types = { '.png': 'image/png', '.webp': 'image/webp', '.gif': 'image/gif', '.heic': 'image/heic' };
  s.type(types[path.extname(o.receipt).toLowerCase()] || 'image/jpeg');
  s.send(Buffer.from(await data.arrayBuffer()));
}));

app.patch('/api/orders/:id', admin, wrap(async (q, s) => {
  const { data: o } = await supabase.from('orders').select('*').eq('order_number', String(q.params.id)).maybeSingle();
  if (!o) return s.status(404).json({ error: 'الطلب غير موجود' });

  const allowed = ['جديد', 'تم التأكيد', 'تم التوصيل', 'ملغي'];
  const newStatus = String(q.body.status || '').trim();
  if (!allowed.includes(newStatus)) return s.status(400).json({ error: 'حالة الطلب غير صحيحة' });

  if (o.status === 'ملغي' && newStatus !== 'ملغي')
    return s.status(400).json({ error: 'الطلب الملغي ما يرجع، سوّي طلب جديد' });

  if (newStatus === 'ملغي' && o.status !== 'ملغي') {
    for (const l of o.items || []) if (l.productId) await adjustStock(l.productId, l.qty);
  }
  const { error } = await supabase.from('orders').update({ status: newStatus }).eq('id', o.id);
  if (error) throw error;
  s.json({ ok: true, status: newStatus });
}));

app.delete('/api/orders/:id', admin, wrap(async (q, s) => {
  const { data: o } = await supabase.from('orders').select('id,receipt').eq('order_number', String(q.params.id)).maybeSingle();
  if (!o) return s.status(404).json({ error: 'لم يتم العثور على الطلب رقم ' + q.params.id });
  const { error } = await supabase.from('orders').delete().eq('id', o.id);
  if (error) throw error;
  await removeFile(RCPT_BUCKET, o.receipt);
  s.json({ ok: true });
}));

// أخطاء رفع الملفات
app.use((err, q, s, next) => {
  console.error(err);
  s.status(400).json({ error: err.code === 'LIMIT_FILE_SIZE' ? 'الصورة كبيرة، الحد 8 ميجا' : 'صار خطأ في رفع الملف' });
});

app.listen(PORT, () => console.log('المتجر شغال: http://localhost:' + PORT + '  |  الإدارة: /admin.html'));
