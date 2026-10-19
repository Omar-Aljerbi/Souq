const express=require('express'),D=require('better-sqlite3'),bc=require('bcryptjs'),jwt=require('jsonwebtoken'),fs=require('fs'),path=require('path');
const SECRET=process.env.JWT_SECRET||'dev-secret-change-me',SHIP=2;
const db=new D('shop.db');db.pragma('journal_mode=WAL');db.pragma('foreign_keys=ON');
const MAP={حمرا:'احمر',زرقا:'ازرق',خضرا:'اخضر',سودا:'اسود',بيضا:'ابيض',صفرا:'اصفر',ورديه:'وردي'};
const norm=s=>(s||'').toString().toLowerCase().replace(/[أإآ]/g,'ا').replace(/ة/g,'ه').replace(/ى/g,'ي').replace(/ء/g,'');
db.function('n',{deterministic:true},norm);
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,phone TEXT,password TEXT NOT NULL,role TEXT DEFAULT 'customer');
CREATE TABLE IF NOT EXISTS stores(id INTEGER PRIMARY KEY,user_id INTEGER UNIQUE REFERENCES users(id),name TEXT NOT NULL,description TEXT,city TEXT,status TEXT DEFAULT 'pending',created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY,store_id INTEGER NOT NULL REFERENCES stores(id),name TEXT NOT NULL,description TEXT,category TEXT,price REAL NOT NULL,image TEXT,active INTEGER DEFAULT 1,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS variants(id INTEGER PRIMARY KEY,product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,size TEXT,color TEXT,stock INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS favorites(user_id INTEGER,product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,PRIMARY KEY(user_id,product_id));
CREATE TABLE IF NOT EXISTS cart(id INTEGER PRIMARY KEY,user_id INTEGER,variant_id INTEGER REFERENCES variants(id) ON DELETE CASCADE,qty INTEGER,UNIQUE(user_id,variant_id));
CREATE TABLE IF NOT EXISTS coupons(id INTEGER PRIMARY KEY,code TEXT UNIQUE,percent INTEGER,min_order REAL DEFAULT 0,active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY,user_id INTEGER,total REAL,discount REAL,coupon TEXT,name TEXT,phone TEXT,city TEXT,address TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS order_items(id INTEGER PRIMARY KEY,order_id INTEGER REFERENCES orders(id),store_id INTEGER,product_id INTEGER,name TEXT,size TEXT,color TEXT,price REAL,qty INTEGER,status TEXT DEFAULT 'جديد');
CREATE TABLE IF NOT EXISTS reviews(id INTEGER PRIMARY KEY,user_id INTEGER,product_id INTEGER REFERENCES products(id) ON DELETE CASCADE,rating INTEGER,comment TEXT,created_at TEXT DEFAULT CURRENT_TIMESTAMP,UNIQUE(user_id,product_id));
CREATE INDEX IF NOT EXISTS i_p_store ON products(store_id);CREATE INDEX IF NOT EXISTS i_p_cat ON products(category);CREATE INDEX IF NOT EXISTS i_p_price ON products(price);
CREATE INDEX IF NOT EXISTS i_v_p ON variants(product_id);CREATE INDEX IF NOT EXISTS i_v_color ON variants(color);CREATE INDEX IF NOT EXISTS i_oi_store ON order_items(store_id);CREATE INDEX IF NOT EXISTS i_o_user ON orders(user_id);CREATE INDEX IF NOT EXISTS i_r_p ON reviews(product_id);`);
if(!db.prepare("SELECT 1 FROM users WHERE role='admin'").get())db.prepare("INSERT INTO users(name,email,password,role) VALUES('المدير','admin@souq.jo',?, 'admin')").run(bc.hashSync(process.env.ADMIN_PASS||'admin123',10));
fs.mkdirSync('public/uploads',{recursive:true});
const app=express();app.use(express.json({limit:'6mb'}));app.use(express.static('public'));
const bad=(m,s=400)=>{const e=new Error(m);e.status=s;throw e};
const A=f=>(q,r)=>{try{r.json(f(q,r))}catch(e){r.status(e.status||400).json({error:e.message})}};
const auth=(...roles)=>(q,r,n)=>{try{q.u=jwt.verify((q.headers.authorization||'').slice(7),SECRET);if(roles.length&&!roles.includes(q.u.role))return r.status(403).json({error:'غير مسموح'});n()}catch{r.status(401).json({error:'سجّل الدخول أولاً'})}};
const store=u=>db.prepare('SELECT * FROM stores WHERE user_id=?').get(u);
const myStore=q=>{const s=store(q.u.id);if(!s||s.status!=='approved')bad('متجرك غير مفعّل بعد',403);return s};

// ---- Auth
app.post('/api/register',A(q=>{const{name,email,phone,password,role,store_name,city,description}=q.body,v=role==='vendor';
if(!name||!email||!password||password.length<6)bad('البيانات ناقصة (كلمة السر 6 أحرف على الأقل)');if(v&&!store_name)bad('اسم المتجر مطلوب');
try{return db.transaction(()=>{const id=db.prepare('INSERT INTO users(name,email,phone,password,role) VALUES(?,?,?,?,?)').run(name,email.toLowerCase(),phone,bc.hashSync(password,10),v?'vendor':'customer').lastInsertRowid;
if(v)db.prepare('INSERT INTO stores(user_id,name,description,city) VALUES(?,?,?,?)').run(id,store_name,description||'',city||'');return{ok:1,pending:v}})()}catch(e){if(/UNIQUE/.test(e.message))bad('البريد مسجّل مسبقاً');throw e}}));
app.post('/api/login',A(q=>{const u=db.prepare('SELECT * FROM users WHERE email=?').get((q.body.email||'').toLowerCase());
if(!u||!bc.compareSync(q.body.password||'',u.password))bad('بيانات الدخول غير صحيحة',401);
return{token:jwt.sign({id:u.id,role:u.role},SECRET,{expiresIn:'30d'}),user:{id:u.id,name:u.name,role:u.role,phone:u.phone},store:store(u.id)}}));

// ---- Public catalog
app.get('/api/products',A(q=>{const{q:s,category,color,size,min,max,sort,store:st}=q.query,pg=Math.max(1,+q.query.page||1),L=24;
const w=["s.status='approved'","p.active=1"],a=[];
for(let x of norm(s).split(/\s+/).filter(Boolean)){x=x.replace(/^ال/,'');const l='%'+(MAP[x]||x)+'%';w.push("(n(p.name) LIKE ? OR n(p.category) LIKE ? OR n(p.description) LIKE ? OR EXISTS(SELECT 1 FROM variants v WHERE v.product_id=p.id AND n(v.color) LIKE ?))");a.push(l,l,l,l)}
if(category){w.push('p.category=?');a.push(category)}if(st){w.push('p.store_id=?');a.push(st)}
if(color){w.push('EXISTS(SELECT 1 FROM variants v WHERE v.product_id=p.id AND v.color=? AND v.stock>0)');a.push(color)}
if(size){w.push('EXISTS(SELECT 1 FROM variants v WHERE v.product_id=p.id AND v.size=? AND v.stock>0)');a.push(size)}
if(min){w.push('p.price>=?');a.push(+min)}if(max){w.push('p.price<=?');a.push(+max)}
const ord={price_asc:'p.price ASC',price_desc:'p.price DESC',rating:'rating DESC'}[sort]||'p.id DESC',W=w.join(' AND ');
const total=db.prepare(`SELECT COUNT(*) c FROM products p JOIN stores s ON s.id=p.store_id WHERE ${W}`).get(...a).c;
const items=db.prepare(`SELECT p.id,p.name,p.price,p.image,p.category,s.name store,s.id store_id,(SELECT ROUND(AVG(rating),1) FROM reviews WHERE product_id=p.id) rating FROM products p JOIN stores s ON s.id=p.store_id WHERE ${W} ORDER BY ${ord} LIMIT ? OFFSET ?`).all(...a,L,(pg-1)*L);
return{items,total,pages:Math.ceil(total/L)}}));
app.get('/api/products/:id',A(q=>{const p=db.prepare("SELECT p.*,s.name store,s.city store_city FROM products p JOIN stores s ON s.id=p.store_id WHERE p.id=? AND p.active=1 AND s.status='approved'").get(q.params.id);if(!p)bad('المنتج غير موجود',404);
p.variants=db.prepare('SELECT id,size,color,stock FROM variants WHERE product_id=?').all(p.id);
p.reviews=db.prepare('SELECT r.rating,r.comment,r.created_at,u.name FROM reviews r JOIN users u ON u.id=r.user_id WHERE product_id=? ORDER BY r.id DESC LIMIT 50').all(p.id);
p.rating=p.reviews.length?+(p.reviews.reduce((t,r)=>t+r.rating,0)/p.reviews.length).toFixed(1):null;return p}));
app.post('/api/products/:id/reviews',auth(),A(q=>{const{rating,comment}=q.body;if(!(rating>=1&&rating<=5))bad('التقييم من 1 إلى 5');
if(!db.prepare("SELECT 1 FROM order_items i JOIN orders o ON o.id=i.order_id WHERE o.user_id=? AND i.product_id=? AND i.status='تم التسليم'").get(q.u.id,q.params.id))bad('يمكنك تقييم المنتجات التي استلمتها فقط');
db.prepare('INSERT INTO reviews(user_id,product_id,rating,comment) VALUES(?,?,?,?) ON CONFLICT(user_id,product_id) DO UPDATE SET rating=excluded.rating,comment=excluded.comment').run(q.u.id,q.params.id,rating,comment||'');return{ok:1}}));

// ---- Favorites / cart / coupon / orders
app.get('/api/favorites',auth(),A(q=>db.prepare("SELECT p.id,p.name,p.price,p.image,s.name store FROM favorites f JOIN products p ON p.id=f.product_id JOIN stores s ON s.id=p.store_id WHERE f.user_id=?").all(q.u.id)));
app.post('/api/favorites/:id',auth(),A(q=>{const r=db.prepare('DELETE FROM favorites WHERE user_id=? AND product_id=?').run(q.u.id,q.params.id);if(!r.changes)db.prepare('INSERT INTO favorites VALUES(?,?)').run(q.u.id,q.params.id);return{fav:!r.changes}}));
app.get('/api/cart',auth(),A(q=>db.prepare('SELECT c.id,c.qty,v.size,v.color,v.stock,p.id pid,p.name,p.price,p.image FROM cart c JOIN variants v ON v.id=c.variant_id JOIN products p ON p.id=v.product_id WHERE c.user_id=?').all(q.u.id)));
app.post('/api/cart',auth(),A(q=>{const v=db.prepare('SELECT * FROM variants WHERE id=?').get(q.body.variant_id);if(!v||v.stock<1)bad('غير متوفر');
db.prepare('INSERT INTO cart(user_id,variant_id,qty) VALUES(?,?,1) ON CONFLICT(user_id,variant_id) DO UPDATE SET qty=MIN(qty+1,?)').run(q.u.id,v.id,v.stock);return{ok:1}}));
app.delete('/api/cart/:id',auth(),A(q=>{db.prepare('DELETE FROM cart WHERE id=? AND user_id=?').run(q.params.id,q.u.id);return{ok:1}}));
const coupon=(code,sub)=>{if(!code)return null;const c=db.prepare('SELECT * FROM coupons WHERE code=? AND active=1').get(code.trim().toUpperCase());if(!c)bad('كوبون غير صالح');if(sub<c.min_order)bad('الحد الأدنى للطلب '+c.min_order+' د.أ');return c};
app.post('/api/coupon',auth(),A(q=>{const sub=db.prepare('SELECT SUM(c.qty*p.price) t FROM cart c JOIN variants v ON v.id=c.variant_id JOIN products p ON p.id=v.product_id WHERE c.user_id=?').get(q.u.id).t||0;const c=coupon(q.body.code,sub);return{percent:c.percent,discount:+(sub*c.percent/100).toFixed(2)}}));
app.post('/api/orders',auth(),A(q=>{const{name,phone,city,address,coupon:code}=q.body;if(!name||!phone||!city||!address)bad('أكمل بيانات التوصيل');
return db.transaction(()=>{const it=db.prepare('SELECT c.id cid,c.qty,v.id vid,v.size,v.color,v.stock,p.id pid,p.name,p.price,p.store_id FROM cart c JOIN variants v ON v.id=c.variant_id JOIN products p ON p.id=v.product_id WHERE c.user_id=?').all(q.u.id);
if(!it.length)bad('السلة فارغة');for(const i of it)if(i.qty>i.stock)bad('الكمية المطلوبة غير متوفرة: '+i.name);
const sub=it.reduce((t,i)=>t+i.qty*i.price,0),c=coupon(code,sub),disc=c?+(sub*c.percent/100).toFixed(2):0,total=+(sub-disc+SHIP).toFixed(2);
const oid=db.prepare('INSERT INTO orders(user_id,total,discount,coupon,name,phone,city,address) VALUES(?,?,?,?,?,?,?,?)').run(q.u.id,total,disc,c?c.code:null,name,phone,city,address).lastInsertRowid;
for(const i of it){db.prepare('INSERT INTO order_items(order_id,store_id,product_id,name,size,color,price,qty) VALUES(?,?,?,?,?,?,?,?)').run(oid,i.store_id,i.pid,i.name,i.size,i.color,i.price,i.qty);db.prepare('UPDATE variants SET stock=stock-? WHERE id=?').run(i.qty,i.vid)}
db.prepare('DELETE FROM cart WHERE user_id=?').run(q.u.id);return{id:oid,total}})()}));
app.get('/api/orders',auth(),A(q=>db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY id DESC').all(q.u.id).map(o=>({...o,items:db.prepare('SELECT name,size,color,price,qty,status FROM order_items WHERE order_id=?').all(o.id)}))));

// ---- Vendor
app.post('/api/upload',auth('vendor'),A(q=>{const m=/^data:image\/(png|jpe?g|webp);base64,(.+)$/.exec(q.body.data||'');if(!m)bad('صورة غير صالحة');const f=Date.now()+'-'+q.u.id+'.'+m[1].replace('jpeg','jpg');fs.writeFileSync(path.join('public/uploads',f),Buffer.from(m[2],'base64'));return{url:'/uploads/'+f}}));
app.get('/api/vendor/products',auth('vendor'),A(q=>{const s=myStore(q);return db.prepare('SELECT * FROM products WHERE store_id=? ORDER BY id DESC').all(s.id).map(p=>({...p,variants:db.prepare('SELECT id,size,color,stock FROM variants WHERE product_id=?').all(p.id)}))}));
app.post('/api/vendor/products',auth('vendor'),A(q=>{const s=myStore(q),{name,description,category,price,image,variants}=q.body;if(!name||!(price>0)||!Array.isArray(variants)||!variants.length)bad('أدخل الاسم والسعر والمخزون');
return db.transaction(()=>{const id=db.prepare('INSERT INTO products(store_id,name,description,category,price,image) VALUES(?,?,?,?,?,?)').run(s.id,name,description||'',category||'',+price,image||'').lastInsertRowid;
for(const v of variants)db.prepare('INSERT INTO variants(product_id,size,color,stock) VALUES(?,?,?,?)').run(id,v.size||null,v.color||null,Math.max(0,+v.stock||0));return{id}})()}));
app.put('/api/vendor/products/:id',auth('vendor'),A(q=>{const s=myStore(q),{price,name}=q.body;db.prepare('UPDATE products SET price=COALESCE(?,price),name=COALESCE(?,name) WHERE id=? AND store_id=?').run(price>0?+price:null,name||null,q.params.id,s.id);return{ok:1}}));
app.put('/api/vendor/variants/:id',auth('vendor'),A(q=>{const s=myStore(q);db.prepare('UPDATE variants SET stock=? WHERE id=? AND product_id IN(SELECT id FROM products WHERE store_id=?)').run(Math.max(0,+q.body.stock||0),q.params.id,s.id);return{ok:1}}));
app.delete('/api/vendor/products/:id',auth('vendor'),A(q=>{const s=myStore(q);db.prepare('DELETE FROM products WHERE id=? AND store_id=?').run(q.params.id,s.id);return{ok:1}}));
app.get('/api/vendor/orders',auth('vendor'),A(q=>{const s=myStore(q);return db.prepare('SELECT i.*,o.name cust,o.phone,o.city,o.address,o.created_at FROM order_items i JOIN orders o ON o.id=i.order_id WHERE i.store_id=? ORDER BY i.id DESC LIMIT 200').all(s.id)}));
const ST=['جديد','قيد التجهيز','تم الشحن','تم التسليم','ملغي'];
app.put('/api/vendor/items/:id',auth('vendor'),A(q=>{const s=myStore(q);if(!ST.includes(q.body.status))bad('حالة غير صالحة');db.prepare('UPDATE order_items SET status=? WHERE id=? AND store_id=?').run(q.body.status,q.params.id,s.id);return{ok:1}}));

// ---- Admin
app.get('/api/admin/stats',auth('admin'),A(()=>({users:db.prepare("SELECT COUNT(*) c FROM users WHERE role='customer'").get().c,stores:db.prepare("SELECT COUNT(*) c FROM stores WHERE status='approved'").get().c,products:db.prepare('SELECT COUNT(*) c FROM products').get().c,orders:db.prepare('SELECT COUNT(*) c FROM orders').get().c,sales:db.prepare('SELECT COALESCE(SUM(total),0) t FROM orders').get().t})));
app.get('/api/admin/stores',auth('admin'),A(()=>db.prepare('SELECT s.*,u.email,u.phone FROM stores s JOIN users u ON u.id=s.user_id ORDER BY s.status=\'pending\' DESC,s.id DESC').all()));
app.put('/api/admin/stores/:id',auth('admin'),A(q=>{if(!['approved','rejected','pending'].includes(q.body.status))bad('حالة غير صالحة');db.prepare('UPDATE stores SET status=? WHERE id=?').run(q.body.status,q.params.id);return{ok:1}}));
app.get('/api/admin/coupons',auth('admin'),A(()=>db.prepare('SELECT * FROM coupons ORDER BY id DESC').all()));
app.post('/api/admin/coupons',auth('admin'),A(q=>{const{code,percent,min_order}=q.body;if(!code||!(percent>0&&percent<=90))bad('أدخل كوداً ونسبة بين 1 و 90');try{db.prepare('INSERT INTO coupons(code,percent,min_order) VALUES(?,?,?)').run(code.trim().toUpperCase(),+percent,+min_order||0)}catch{bad('الكود موجود')}return{ok:1}}));
app.delete('/api/admin/coupons/:id',auth('admin'),A(q=>{db.prepare('DELETE FROM coupons WHERE id=?').run(q.params.id);return{ok:1}}));
app.listen(process.env.PORT||3000,()=>console.log('http://localhost:'+(process.env.PORT||3000)));
