const express = require('express'), multer = require('multer');
const fs = require('fs'), path = require('path'), crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_PASS = process.env.ADMIN_PASS || 'change-me';   // غيّر كلمة السر
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DB = path.join(DATA_DIR, 'data.json');
const UP = path.join(DATA_DIR, 'uploads');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(UP, { recursive: true });

const read = () => {
  try {
    const d = JSON.parse(fs.readFileSync(DB));
    if (!d.users) d.users = [];
    if (!d.products) d.products = [];
    if (!d.orders) d.orders = [];
    return d;
  } catch {
    return { products: [], orders: [], users: [] };
  }
};
const save = d => fs.writeFileSync(DB, JSON.stringify(d, null, 1));
const id = () => crypto.randomBytes(6).toString('hex');

const upload = multer({
  storage: multer.diskStorage({
    destination: UP,
    filename: (q, f, cb) => cb(null, id() + path.extname(f.originalname).toLowerCase())
  }),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (q, f, cb) => cb(null, /^image\//.test(f.mimetype))
});

const admin = (q, s, next) => q.get('x-admin') === ADMIN_PASS ? next() : s.status(401).json({ error: 'كلمة السر غير صحيحة' });
// ---- حسابات العملاء ----
const customerSessions = new Map();

function customerAuth(q, s, next) {
  const token = q.cookies?.customerSession;
  const userId = customerSessions.get(token);

  if (!userId) {
    return s.status(401).json({ error: 'سجلي الدخول أولاً' });
  }

  q.customerId = userId;
  next();
}

function createCustomerSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  customerSessions.set(token, userId);
  return token;
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

const app = express();
app.set('trust proxy', 1);
app.use(express.json());


app.use((q, s, next) => {
  const cookieHeader = q.headers.cookie || '';

  q.cookies = {};

  cookieHeader.split(';').forEach(cookie => {
    const [name, ...value] = cookie.trim().split('=');
    if (name) {
      q.cookies[name] = decodeURIComponent(value.join('='));
    }
  });

  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// عرض صور المنتجات فقط، ومنع الوصول المباشر لباقي الملفات
app.get('/uploads/:filename', (q, s) => {
  const filename = path.basename(q.params.filename);
  const d = read();

  const isProductImage = d.products.some(p =>
    p.image === '/uploads/' + filename
  );

  if (!isProductImage) {
    return s.sendStatus(404);
  }

  s.sendFile(path.join(UP, filename));
});
// إنشاء حساب جديد
// إنشاء حساب جديد
app.post('/api/register', (q, s) => {
  const { name, phone, password } = q.body;

  if (!name || !phone || !password) {
    return s.status(400).json({ error: 'عبّي جميع البيانات' });
  }

  if (String(password).length < 8) {
    return s.status(400).json({ error: 'كلمة المرور يجب أن تكون 8 أحرف على الأقل' });
  }

  const d = read();
  const cleanPhone = String(phone).trim();

  if (d.users.some(u => u.phone === cleanPhone)) {
    return s.status(409).json({ error: 'رقم الهاتف مسجل مسبقاً' });
  }

  const salt = crypto.randomBytes(16).toString('hex');

  const user = {
    id: id(),
    name: String(name).trim(),
    phone: cleanPhone,
    salt,
    passwordHash: hashPassword(String(password), salt)
  };

  d.users.push(user);
  save(d);

  const token = createCustomerSession(user.id);

  s.cookie('customerSession', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 7 * 24 * 60 * 60 * 1000
  });

  s.json({
    ok: true,
    user: { id: user.id, name: user.name, phone: user.phone }
  });
});

// تسجيل دخول العميل
app.post('/api/login', (q, s) => {
  const { phone, password } = q.body;
  const d = read();

  const user = d.users.find(u => u.phone === String(phone || '').trim());

  if (!user || !password) {
    return s.status(401).json({ error: 'رقم الهاتف أو كلمة المرور غير صحيحة' });
  }

  const hash = hashPassword(String(password), user.salt);

  const valid =
    hash.length === user.passwordHash.length &&
    crypto.timingSafeEqual(
      Buffer.from(hash, 'hex'),
      Buffer.from(user.passwordHash, 'hex')
    );

  if (!valid) {
    return s.status(401).json({ error: 'رقم الهاتف أو كلمة المرور غير صحيحة' });
  }

 const token = createCustomerSession(user.id);

s.cookie('customerSession', token, {
  httpOnly: true,
  sameSite: 'lax',
 secure: process.env.NODE_ENV === 'production',
  maxAge: 7 * 24 * 60 * 60 * 1000
});

s.json({
  ok: true,
  user: { id: user.id, name: user.name, phone: user.phone }
});
});

// معلومات حساب العميل الحالي
app.get('/api/me', customerAuth, (q, s) => {
  const user = read().users.find(u => u.id === q.customerId);

  if (!user) return s.sendStatus(404);

  s.json({
    id: user.id,
    name: user.name,
    phone: user.phone
  });
});


// تسجيل الخروج
app.post('/api/logout', customerAuth, (q, s) => {
  const token = q.cookies?.customerSession;

  customerSessions.delete(token);

  s.clearCookie('customerSession', {
    httpOnly: true,
    sameSite: 'lax',
   secure: process.env.NODE_ENV === 'production',
  });

  s.json({ ok: true });
});
// طلبات العميل
app.get('/api/my-orders', customerAuth, (q, s) => {
  const d = read();

  const orders = d.orders.filter(
    o => o.customerId === q.customerId
  );

  s.json(orders);
});

// ---- المنتجات ----
app.get('/api/products', (q, s) => s.json(read().products));


app.post('/api/products', admin, upload.single('image'), (q, s) => {
  const { name, price, desc, category, quantity } = q.body;

  const stock = Number(quantity);

  if (!name || price === undefined || price === '') {
    return s.status(400).json({ error: 'الاسم والسعر مطلوبين' });
  }

  if (quantity === undefined || quantity === '' ||
      !Number.isInteger(stock) || stock < 0) {
    return s.status(400).json({ error: 'أدخلي كمية صحيحة' });
  }

  const d = read();

  d.products.unshift({
    id: id(),
    name,
    price: +price,
    desc: desc || '',
    category: category || '',
    quantity: stock,
    image: q.file ? '/uploads/' + q.file.filename : '',
    soldout: stock === 0
  });

  save(d);
  s.json({ ok: true });
});



app.patch('/api/products/:id', admin, (q, s) => {
  const d = read();
  const p = d.products.find(x => x.id === q.params.id);

  if (!p) return s.sendStatus(404);

  if (q.body.quantity !== undefined) {
    const stock = Number(q.body.quantity);

    if (!Number.isInteger(stock) || stock < 0) {
      return s.status(400).json({ error: 'أدخل كمية صحيحة' });
    }

    p.quantity = stock;
    p.soldout = stock === 0;
  }

  if (q.body.soldout !== undefined) {
    p.soldout = !!q.body.soldout;
  }

  save(d);
  s.json({ ok: true });
});

app.delete('/api/products/:id', admin, (q, s) => {
  const d = read(); d.products = d.products.filter(x => x.id !== q.params.id);
  save(d); s.json({ ok: true });
});

// ---- الطلبات ----
app.post('/api/orders', upload.single('receipt'), (q, s) => {
  const { name, phone, region, place } = q.body;

  let items = [];

  try {
    items = JSON.parse(q.body.items);
  } catch {
    if (q.file) fs.unlinkSync(q.file.path);
    return s.status(400).json({ error: 'بيانات المنتجات غير صحيحة' });
  }

  if (!name || !phone || !region || !place || !q.file || !items.length) {
    if (q.file) fs.unlinkSync(q.file.path);
    return s.status(400).json({ error: 'عبّ كل البيانات وارفق صورة الإيصال' });
  }

  const d = read();

  const lines = [];
  const requiredStock = {};

  for (const item of items) {
    const p = d.products.find(x => x.id === item.id);
    const qty = Number(item.qty);

    if (!p || !Number.isInteger(qty) || qty < 1) {
      fs.unlinkSync(q.file.path);
      return s.status(400).json({ error: 'بيانات المنتج أو الكمية غير صحيحة' });
    }

    requiredStock[p.id] = (requiredStock[p.id] || 0) + qty;

    lines.push({
      name: p.name,
      price: Number(p.price),
      qty,
      note: String(item.note || '').slice(0, 200)
    });
  }

  for (const productId of Object.keys(requiredStock)) {
    const p = d.products.find(x => x.id === productId);
    const available = Number(p.quantity ?? 0);

    if (p.soldout || available < requiredStock[productId]) {
      fs.unlinkSync(q.file.path);
      return s.status(400).json({
        error: `الكمية المتوفرة من ${p.name} غير كافية`
      });
    }
  }

  // خصم الكمية بعد التأكد من توفر جميع المنتجات
  for (const productId of Object.keys(requiredStock)) {
    const p = d.products.find(x => x.id === productId);

    p.quantity -= requiredStock[productId];
    p.soldout = p.quantity === 0;
  }

  const customerToken = q.cookies?.customerSession;
  const customerId = customerSessions.get(customerToken);

  if (!d.nextOrderNumber) {
    const highestId = d.orders.reduce(
      (max, o) => Math.max(max, Number(o.id) || 0), 0
    );

    d.nextOrderNumber = highestId + 1;
  }

  const nextOrderNumber = d.nextOrderNumber;
  d.nextOrderNumber = nextOrderNumber + 1;

  const order = {
    id: String(nextOrderNumber).padStart(2, '0'),
    customerId: customerId || null,
    name,
    phone,
    region,
    place,
    items: lines,
    total: lines.reduce((a, l) => a + l.price * l.qty, 0),
    receipt: '/uploads/' + q.file.filename,
    status: 'جديد'
  };

  d.orders.unshift(order);
  save(d);

  s.json({
    ok: true,
    id: order.id,
    total: order.total
  });
});
// عرض جميع الطلبات للأدمن
app.get('/api/orders', admin, (q, s) => {
  s.json(read().orders);
});

// عرض إيصال الطلب للأدمن فقط
app.get('/api/orders/:id/receipt', admin, (q, s) => {
  const d = read();
  const order = d.orders.find(o => String(o.id) === String(q.params.id));

  if (!order || !order.receipt) {
    return s.sendStatus(404);
  }

  const filename = path.basename(order.receipt);
  const receiptPath = path.join(UP, filename);
console.log('Receipt saved path:', receiptPath);
console.log('Receipt exists:', fs.existsSync(receiptPath));
console.log('Receipt value:', order.receipt);
  if (!fs.existsSync(receiptPath)) {
    return s.sendStatus(404);
  }

  s.sendFile(receiptPath);
});
app.patch('/api/orders/:id', admin, (q, s) => {
  const d = read();

  const o = d.orders.find(
    x => String(x.id) === String(q.params.id)
  );

  if (!o) {
    return s.status(404).json({ error: 'الطلب غير موجود' });
  }

  const allowedStatuses = ['جديد', 'تم التأكيد', 'تم التوصيل', 'ملغي'];
  const newStatus = String(q.body.status || '').trim();

  if (!allowedStatuses.includes(newStatus)) {
    return s.status(400).json({ error: 'حالة الطلب غير صحيحة' });
  }

  o.status = newStatus;
  save(d);

  s.json({ ok: true, status: o.status });
});
// حذف الطلب
app.delete('/api/orders/:id', admin, (q, s) => {
  const d = read();

  const orderId = String(q.params.id);

  const oldLength = d.orders.length;

  d.orders = d.orders.filter(o => String(o.id) !== orderId);

  if (d.orders.length === oldLength) {
    return s.status(404).json({
      error: 'لم يتم العثور على الطلب رقم ' + orderId,
      availableOrders: d.orders.map(o => o.id)
    });
  }

  save(d);
  s.json({ ok: true });
});

console.log('DELETE ROUTE IS READY');
 


app.listen(PORT, () => console.log('المتجر شغال: http://localhost:' + PORT + '  |  الإدارة: /admin.html'));
