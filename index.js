const express     = require('express');
const admin       = require('firebase-admin');
const bodyParser  = require('body-parser');
const cors        = require('cors');
const bcrypt      = require('bcryptjs');
const { google }  = require('googleapis');
const rateLimit   = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1); // ✅ Render একটা proxy-এর পেছনে চলে, এটা না থাকলে express-rate-limit
                            // ERR_ERL_UNEXPECTED_X_FORWARDED_FOR এরর দেয়
app.use(cors());
app.use(bodyParser.json());

// ── Firebase Admin initialize ──
const serviceAccount = JSON.parse(process.env.serviceAccountKey);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  // ✅ নতুন, ঐচ্ছিক: FIREBASE_DATABASE_URL সেট থাকলে Realtime Database-ও ব্যবহার করা যাবে
  // (Request Monitoring ফিচারের জন্য দরকার)। সেট না থাকলে আগের মতোই শুধু Firestore ব্যবহৃত হবে —
  // এতে existing কোনো ফিচার ভাঙে না।
  ...(process.env.FIREBASE_DATABASE_URL ? { databaseURL: process.env.FIREBASE_DATABASE_URL } : {})
});

const db = admin.firestore();
// ✅ নতুন: Realtime Database reference (শুধু URL সেট থাকলেই তৈরি হবে, নাহলে null থাকবে)
let rtdb = null;
if (process.env.FIREBASE_DATABASE_URL) {
  try {
    rtdb = admin.database();
  } catch (e) {
    console.error('Realtime Database init failed:', e.message);
  }
}

// ════════════════════════════════════════════════════════════
// HELPERS
// ════════════════════════════════════════════════════════════

function isValidAppId(appId) {
  return appId && /^[a-zA-Z0-9._\-]{3,100}$/.test(appId);
}

function tokenDocId(token) {
  return token.replace(/[^a-zA-Z0-9]/g, '').substring(0, 20);
}

function devicesRef(appId) {
  return db.collection('push_tokens').doc(appId).collection('devices');
}

function appMetaRef(appId) {
  return db.collection('push_app_meta').doc(appId);
}

// ════════════════════════════════════════════════════════════
// ROUTES
// ════════════════════════════════════════════════════════════

app.get('/', (req, res) => {
  res.send('Wevlo Push Notification Server is Running!');
});

// ── Debug: দেখো এখন সার্ভারে কোন credential লোড হয়েছে ──
// GET /debug
app.get('/debug', (req, res) => {
  res.json({
    project_id:      serviceAccount.project_id,
    client_email:    serviceAccount.client_email,
    private_key_id:  serviceAccount.private_key_id,
    private_key_len: (serviceAccount.private_key || '').length
  });
});

// ── Debug: appId রেজিস্টার্ড আছে কিনা এবং কয়টা token আছে ──
// GET /app-status?appId=com.myapp.xyz
app.get('/app-status', async (req, res) => {
  const { appId } = req.query;
  if (!isValidAppId(appId)) return res.status(400).json({ success: false, error: 'valid appId required' });

  try {
    const metaDoc  = await appMetaRef(appId).get();
    const tokenSnap = await devicesRef(appId).get();
    res.json({
      success:      true,
      appId,
      registered:   metaDoc.exists,
      registeredAt: metaDoc.exists ? metaDoc.data().registeredAt : null,
      tokenCount:   tokenSnap.size
    });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Register App (APK build থেকে password সেট হয়) ──
// POST /register-app  { appId, password }
app.post('/register-app', async (req, res) => {
  const { appId } = req.body;
  if (!isValidAppId(appId)) return res.status(400).json({ success: false, error: 'valid appId required' });

  try {
    const ref = appMetaRef(appId);
    const doc = await ref.get();

    await ref.set({
      appId,
      registeredAt: doc.exists ? doc.data().registeredAt : Date.now(),
      updatedAt:    Date.now()
    }, { merge: true });

    console.log(`[${appId}] App registered/updated`);
    res.json({ success: true, message: 'app registered' });
  } catch (e) {
    console.error('Register-app error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Register Token (APK থেকে আসে) ──
// POST /register-token  { token, appId, userAgent?, password? }
app.post('/register-token', async (req, res) => {
  const { token, appId, userAgent } = req.body;

  if (!token)               return res.status(400).json({ success: false, error: 'token required' });
  if (!isValidAppId(appId)) return res.status(400).json({ success: false, error: 'valid appId required' });

  try {
    await devicesRef(appId).doc(tokenDocId(token)).set({
      token,
      appId,
      userAgent:    userAgent || '',
      registeredAt: Date.now(),
      updatedAt:    Date.now()
    }, { merge: true });

    console.log(`[${appId}] Token registered: ${token.substring(0, 20)}...`);
    res.json({ success: true });
  } catch (e) {
    console.error('Register error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Get tokens by appId (password required) ──
// GET /tokens?appId=com.myapp.xyz&password=xxx
app.get('/tokens', async (req, res) => {
  const { appId } = req.query;
  if (!isValidAppId(appId)) return res.status(400).json({ success: false, error: 'valid appId required' });

  // Password check disabled — সব request password ছাড়াই allow

  try {
    const snap   = await devicesRef(appId).get();
    const tokens = snap.docs.map(d => ({
      token:        d.data().token,
      registeredAt: d.data().registeredAt,
      userAgent:    d.data().userAgent || ''
    }));
    res.json({ success: true, appId, count: tokens.length, tokens });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Send to one token (password required) ──
// POST /send-notification  { token, title, body, password, appId }
app.post('/send-notification', async (req, res) => {
  const { token, title, body, imageUrl } = req.body;
  if (!token) return res.status(400).json({ success: false, error: 'token required' });

  // Password check disabled — password ছাড়াই allow

  try {
    const t = title || 'Notification';
    const b = body  || '';

    const message = {
      token,
      data: { title: t, body: b, ...(imageUrl ? { imageUrl } : {}) },
      android: { priority: 'high' }
    };

    const msgId = await admin.messaging().send(message);
    res.json({ success: true, messageId: msgId });
  } catch (e) {
    console.error('Send error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Send to ALL tokens of an appId (password required) ──
// POST /send-all  { appId, title, body, password }
app.post('/send-all', async (req, res) => {
  const { appId, title, body, imageUrl } = req.body;
  if (!isValidAppId(appId)) return res.status(400).json({ success: false, error: 'valid appId required' });

  // Password check disabled — password ছাড়াই allow

  try {
    const snap = await devicesRef(appId).get();
    if (snap.empty) return res.json({ success: false, error: 'No tokens found for this app' });

    const tokens = snap.docs.map(d => d.data().token).filter(Boolean);
    const t = title || 'Notification';
    const b = body  || '';
    const messages = tokens.map(token => ({
      token,
      data: { title: t, body: b, ...(imageUrl ? { imageUrl } : {}) },
      android: { priority: 'high' }
    }));

    const result = await admin.messaging().sendEach(messages);
    console.log(`[${appId}] Sent: ${result.successCount} ok, ${result.failureCount} failed`);

    // invalid token গুলো Firestore থেকে delete করো
    const batch = db.batch();
    let removed = 0;
    result.responses.forEach((r, i) => {
      if (!r.success) { batch.delete(snap.docs[i].ref); removed++; }
    });
    if (removed > 0) await batch.commit();

    res.json({
      success:      true,
      appId,
      total:        tokens.length,
      successCount: result.successCount,
      failureCount: result.failureCount
    });
  } catch (e) {
    console.error('Send-all error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Delete a token (password required) ──
// DELETE /token?appId=com.myapp&token=xxx&password=yyy
app.delete('/token', async (req, res) => {
  const { appId, token } = req.query;
  if (!isValidAppId(appId) || !token) return res.status(400).json({ success: false, error: 'appId and token required' });

  // Password check disabled — password ছাড়াই allow

  try {
    await devicesRef(appId).doc(tokenDocId(token)).delete();
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: e.message });
  }
});

// ════════════════════════════════════════════════════════════
// ✅ NEW: REQUEST MONITORING → ADMIN PUSH NOTIFICATION
// (existing Push Notification System reuse করে, নতুন কোনো token/send সিস্টেম তৈরি করা হয়নি)
// ════════════════════════════════════════════════════════════

const ADMIN_APP_ID = process.env.ADMIN_APP_ID || 'com.hrsecurepocketadmin';

// ভবিষ্যতে নতুন request type যোগ করতে হলে শুধু এই array-তে একটা entry বাড়ালেই হবে।
const REQUEST_TYPES = [
  { key: 'order',        path: 'productOrders',        label: 'Order' },
  { key: 'verification', path: 'verificationRequests',  label: 'Account Verification' },
  { key: 'withdraw',     path: 'withdrawals',           label: 'Withdraw' },
  { key: 'deposit',      path: 'deposits',              label: 'Deposit' }
];

// Admin Panel-এর dashboard যে কনভেনশনে pending গোনে (status না থাকলেও pending ধরা হয়),
// এখানেও ঠিক সেই একই নিয়ম মানা হচ্ছে, যাতে সংখ্যা মিলে যায়।
function isPendingStatus(status) {
  const s = (status || 'pending').toString().toLowerCase();
  return s === 'pending';
}

// existing devicesRef()/admin.messaging() ব্যবহার করেই পাঠানো হচ্ছে — /send-all যেভাবে পাঠায় ঠিক সেভাবেই,
// শুধু appId এখানে fixed (ADMIN_APP_ID)। /send-all রুটের কোনো কোড এখানে বদলানো/সরানো হয়নি।
async function sendPushToApp(appId, title, body, imageUrl) {
  const snap = await devicesRef(appId).get();
  if (snap.empty) return { success: false, error: `No registered device tokens for appId "${appId}"` };

  const tokens = snap.docs.map(d => d.data().token).filter(Boolean);
  const messages = tokens.map(token => ({
    token,
    data: { title, body, ...(imageUrl ? { imageUrl } : {}) },
    android: { priority: 'high' }
  }));

  const result = await admin.messaging().sendEach(messages);

  const batch = db.batch();
  let removed = 0;
  result.responses.forEach((r, i) => {
    if (!r.success) { batch.delete(snap.docs[i].ref); removed++; }
  });
  if (removed > 0) await batch.commit();

  return { success: true, total: tokens.length, successCount: result.successCount, failureCount: result.failureCount };
}

// একটা request-type-এর pending, এখনো-notify-না-হওয়া entry গুলো বের করে,
// প্রতিটাতে notified/lastNotifiedAt বসিয়ে দেয় (Realtime Database-এর existing request record-এই,
// কোনো নতুন collection তৈরি করা হয়নি) — যাতে একই request-এর জন্য বারবার নোটিফিকেশন না যায়।
async function checkPendingRequestsForType(type) {
  if (!rtdb) return { count: 0 };

  const snap = await rtdb.ref(type.path).once('value');
  if (!snap.exists()) return { count: 0 };

  let newCount = 0;
  const updates = {};
  snap.forEach(child => {
    const val = child.val() || {};
    if (!isPendingStatus(val.status)) return;
    if (val.notified === true) return; // আগেই notify করা হয়েছে — spam না হয়

    newCount++;
    updates[`${type.path}/${child.key}/notified`] = true;
    updates[`${type.path}/${child.key}/lastNotifiedAt`] = Date.now();
  });

  if (newCount > 0) await rtdb.ref().update(updates);
  return { count: newCount };
}

async function checkPendingRequests() {
  console.log('Checking pending requests...');

  if (!rtdb) {
    console.error('Request monitoring error: FIREBASE_DATABASE_URL সেট নেই, Realtime Database ব্যবহার করা যাচ্ছে না');
    return;
  }

  try {
    const results = [];
    for (const type of REQUEST_TYPES) {
      try {
        const r = await checkPendingRequestsForType(type);
        if (r.count > 0) results.push({ type, count: r.count });
      } catch (e) {
        // একটা type-এ error হলেও বাকিগুলো চেক চলতে থাকবে
        console.error(`Request monitoring error (${type.path}):`, e.message);
      }
    }

    const totalNew = results.reduce((s, r) => s + r.count, 0);
    if (totalNew === 0) {
      console.log('No new requests found');
      return;
    }

    console.log(`Found ${totalNew} pending requests`);

    const perTypeLines = results.map(r => `${r.count}টি নতুন ${r.type.label} Request এসেছে।`);
    const title = 'HR Secure Pocket - New Request';
    const body = totalNew === 1
      ? perTypeLines[0]
      : `${totalNew}টি নতুন request pending আছে। Admin Panel খুলে দেখুন। ` + perTypeLines.join(' ');

    const sendResult = await sendPushToApp(ADMIN_APP_ID, title, body);
    if (sendResult.success) {
      console.log('Admin notification sent successfully');
    } else {
      console.error('Request monitoring error:', sendResult.error);
    }
  } catch (e) {
    console.error('Request monitoring error:', e.message);
  }
}

function startRequestMonitor() {
  const hours = parseFloat(process.env.REQUEST_CHECK_INTERVAL_HOURS || '2');
  const intervalMs = Math.max(hours > 0 ? hours : 2, 0.01) * 60 * 60 * 1000;

  console.log('Request monitor started');

  // সার্ভার বুট/রিস্টার্ট হওয়ার ৩০ সেকেন্ড পর প্রথম চেক, তারপর প্রতি interval-এ — restart হলেও
  // এই ফাংশনটাই আবার কল হবে (নিচে app.listen() এর ঠিক আগে কল করা হচ্ছে), তাই scheduler নিজে থেকেই আবার চালু হয়ে যায়।
  setTimeout(() => { checkPendingRequests(); }, 30 * 1000);
  setInterval(() => { checkPendingRequests(); }, intervalMs);
}

// ════════════════════════════════════════════════════════════
// ✅ NEW: PASSWORD CHANGE — EMAIL OTP SYSTEM
// ════════════════════════════════════════════════════════════

const OTP_EXPIRY_MINUTES     = parseInt(process.env.OTP_EXPIRY_MINUTES || '5', 10);
const OTP_MAX_ATTEMPTS       = 5;                 // ভুল OTP এর সর্বোচ্চ সংখ্যা
const OTP_REQUEST_LIMIT      = 3;                 // windows এর মধ্যে সর্বোচ্চ কতবার OTP চাওয়া যাবে
const OTP_REQUEST_WINDOW_MIN = 15;
const OTP_VERIFIED_WINDOW_MS = 10 * 60 * 1000;    // verify হওয়ার পর password change করার জন্য সময়সীমা

function otpDocRef(uid) {
  return db.collection('password_otps').doc(uid);
}

function generateOtp() {
  return String(Math.floor(100000 + Math.random() * 900000)); // 6-digit
}

// ✅ Gmail REST API (HTTPS, পোর্ট 443) দিয়ে ইমেইল পাঠানো হয় — raw SMTP (পোর্ট 465/587) ব্যবহার
// করা হয় না, কারণ Render-এর ফ্রি টায়ার SMTP পোর্ট সম্পূর্ণ ব্লক করে রাখে (২০২৫ সাল থেকে)।
// GMAIL_CLIENT_ID / GMAIL_CLIENT_SECRET / GMAIL_REFRESH_TOKEN — Google Cloud Console (OAuth2)
// থেকে বানানো, GMAIL_SENDER_EMAIL সেই একাউন্টের ইমেইল ঠিকানা।
const gmailOAuth2Client = (process.env.GMAIL_CLIENT_ID && process.env.GMAIL_CLIENT_SECRET)
  ? new google.auth.OAuth2(
      process.env.GMAIL_CLIENT_ID,
      process.env.GMAIL_CLIENT_SECRET,
      'https://developers.google.com/oauthplayground'
    )
  : null;
if (gmailOAuth2Client && process.env.GMAIL_REFRESH_TOKEN) {
  gmailOAuth2Client.setCredentials({ refresh_token: process.env.GMAIL_REFRESH_TOKEN });
}

function buildRawEmail(from, to, subject, html) {
  const encodedSubject = `=?utf-8?B?${Buffer.from(subject, 'utf-8').toString('base64')}?=`;
  const message = [
    `From: HR Secure Pocket <${from}>`,
    `To: ${to}`,
    'Content-Type: text/html; charset=utf-8',
    'MIME-Version: 1.0',
    `Subject: ${encodedSubject}`,
    '',
    html
  ].join('\r\n');

  return Buffer.from(message, 'utf-8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

async function sendOtpEmail(toEmail, otp) {
  if (!gmailOAuth2Client || !process.env.GMAIL_REFRESH_TOKEN || !process.env.GMAIL_SENDER_EMAIL) {
    throw new Error('Gmail API not configured (GMAIL_CLIENT_ID/GMAIL_CLIENT_SECRET/GMAIL_REFRESH_TOKEN/GMAIL_SENDER_EMAIL missing)');
  }

  const subject = 'Your Password Change OTP - HR Secure Pocket';
  const html = `<p>আপনার পাসওয়ার্ড পরিবর্তনের OTP কোড:</p>`
      + `<h2 style="letter-spacing:4px">${otp}</h2>`
      + `<p>এই কোডটি <b>${OTP_EXPIRY_MINUTES} মিনিটের</b> জন্য কার্যকর। কাউকে শেয়ার করবেন না।</p>`;

  const raw = buildRawEmail(process.env.GMAIL_SENDER_EMAIL, toEmail, subject, html);

  const gmail = google.gmail({ version: 'v1', auth: gmailOAuth2Client });
  await gmail.users.messages.send({ userId: 'me', requestBody: { raw } });
}

// সাধারণ in-memory per-uid rate limiter (single Render instance ধরে নিয়ে — একাধিক instance-এ
// scale করলে এটা Redis-এর মতো shared store দিয়ে করা লাগবে)
const otpRequestLog = new Map(); // uid -> [timestamps]
function isOtpRequestAllowed(uid) {
  const now = Date.now();
  const windowMs = OTP_REQUEST_WINDOW_MIN * 60 * 1000;
  const list = (otpRequestLog.get(uid) || []).filter(t => now - t < windowMs);
  if (list.length >= OTP_REQUEST_LIMIT) { otpRequestLog.set(uid, list); return false; }
  list.push(now);
  otpRequestLog.set(uid, list);
  return true;
}

// per-IP defense-in-depth (উপরের per-uid limiter-এর পাশাপাশি)
const otpIpLimiter = rateLimit({
  windowMs: OTP_REQUEST_WINDOW_MIN * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false
});

// ⚠️ ডিজাইন নোট: idToken (লগইন থাকা লাগে) এর বদলে email ব্যবহার করা হচ্ছে — কারণ Forgot Password
// ঠিক তখনই দরকার হয় যখন ইউজার লগইনই করতে পারছে না (পাসওয়ার্ড ভুলে গেছে), তখন কোনো idToken থাকে না।
// ইমেইলে OTP পাঠানো আর সেটা সঠিকভাবে verify করাটাই এখানে "সে-ই একাউন্টের মালিক" এর প্রমাণ —
// standard password-reset security pattern। এই একই তিনটা API Login পেজের "Forgot Password"
// এবং Settings পেজের "Change Password" — দুই জায়গাতেই ব্যবহার করা যায়।
async function getUidByEmail(email) {
  try {
    const userRecord = await admin.auth().getUserByEmail(email);
    return userRecord.uid;
  } catch (e) {
    return null; // এই email-এ কোনো একাউন্ট নেই
  }
}

// ── OTP request ──
// POST /request-password-otp   { email }
app.post('/request-password-otp', otpIpLimiter, async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    if (!email) return res.status(400).json({ success: false, error: 'email required' });

    const uid = await getUidByEmail(email);
    // ⚠️ নিরাপত্তার জন্য: email registered না থাকলেও একই success message দেওয়া হয়,
    // যাতে কেউ এই API দিয়ে "কোন কোন ইমেইলে একাউন্ট আছে" যাচাই (enumerate) করতে না পারে।
    if (!uid) {
      console.log(`[password-otp] OTP requested for unregistered email: ${email}`);
      return res.json({ success: true, message: 'যদি এই ইমেইলে একাউন্ট থাকে, OTP পাঠানো হয়েছে' });
    }

    if (!isOtpRequestAllowed(uid)) {
      return res.status(429).json({
        success: false,
        error: `একটু পর আবার চেষ্টা করুন (${OTP_REQUEST_WINDOW_MIN} মিনিটে সর্বোচ্চ ${OTP_REQUEST_LIMIT} বার OTP চাওয়া যায়)`
      });
    }

    const otp = generateOtp();
    const otpHash = await bcrypt.hash(otp, 10); // ⚠️ plain text সেভ হয় না, শুধু hash

    await otpDocRef(uid).set({
      otpHash,
      email,
      attempts: 0,
      verified: false,
      createdAt: Date.now(),
      expiresAt: Date.now() + OTP_EXPIRY_MINUTES * 60 * 1000
    });

    await sendOtpEmail(email, otp);
    console.log(`[password-otp] OTP sent (uid: ${uid})`);
    res.json({ success: true, message: 'যদি এই ইমেইলে একাউন্ট থাকে, OTP পাঠানো হয়েছে' });
  } catch (e) {
    console.error('request-password-otp error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── OTP verify ──
// POST /verify-password-otp   { email, otp }
app.post('/verify-password-otp', async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const { otp } = req.body;
    if (!email)  return res.status(400).json({ success: false, error: 'email required' });
    if (!otp) return res.status(400).json({ success: false, error: 'otp required' });

    const uid = await getUidByEmail(email);
    if (!uid) return res.status(400).json({ success: false, error: 'ভুল OTP' }); // enumerate আটকাতে generic error

    const doc = await otpDocRef(uid).get();
    if (!doc.exists) return res.status(400).json({ success: false, error: 'কোনো OTP request করা হয়নি, আগে request করুন।' });

    const data = doc.data();
    if (Date.now() > data.expiresAt) {
      await otpDocRef(uid).delete();
      return res.status(400).json({ success: false, error: 'OTP মেয়াদ শেষ হয়ে গেছে, আবার request করুন।' });
    }
    if (data.attempts >= OTP_MAX_ATTEMPTS) {
      await otpDocRef(uid).delete();
      return res.status(400).json({ success: false, error: 'অনেকবার ভুল OTP দেওয়া হয়েছে, আবার নতুন OTP request করুন।' });
    }

    const match = await bcrypt.compare(String(otp), data.otpHash);
    if (!match) {
      await otpDocRef(uid).update({ attempts: admin.firestore.FieldValue.increment(1) });
      return res.status(400).json({ success: false, error: 'ভুল OTP' });
    }

    await otpDocRef(uid).update({ verified: true, verifiedAt: Date.now() });
    res.json({ success: true, message: 'OTP verified' });
  } catch (e) {
    console.error('verify-password-otp error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ── Password change (শুধু OTP verify হওয়ার পরেই কাজ করবে) ──
// POST /change-password   { email, newPassword }
app.post('/change-password', async (req, res) => {
  try {
    const email = (req.body.email || '').trim().toLowerCase();
    const { newPassword } = req.body;
    if (!email) return res.status(400).json({ success: false, error: 'email required' });
    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
    }

    const uid = await getUidByEmail(email);
    if (!uid) return res.status(400).json({ success: false, error: 'আগে OTP verify করুন।' });

    const doc = await otpDocRef(uid).get();
    if (!doc.exists || !doc.data().verified) {
      return res.status(400).json({ success: false, error: 'আগে OTP verify করুন।' });
    }
    const data = doc.data();
    if (Date.now() - (data.verifiedAt || 0) > OTP_VERIFIED_WINDOW_MS) {
      await otpDocRef(uid).delete();
      return res.status(400).json({ success: false, error: 'OTP verification-এর মেয়াদ শেষ, আবার শুরু থেকে করুন।' });
    }

    // ⚠️ Firebase Auth নিজেই securely (scrypt) hash করে রাখে — আমরা কোথাও plain text password সেভ করছি না।
    await admin.auth().updateUser(uid, { password: newPassword });
    await otpDocRef(uid).delete(); // one-time ব্যবহার শেষে মুছে ফেলা, replay আটকাতে

    console.log(`[password-otp] Password changed (uid: ${uid})`);
    res.json({ success: true, message: 'Password changed successfully' });
  } catch (e) {
    console.error('change-password error:', e.message);
    res.status(500).json({ success: false, error: e.message });
  }
});

// ════════════════════════════════════════════════════════════
// ✅ NEW: CRASH-SAFETY — temporary DB/network এরর যেন সার্ভার বন্ধ না করে
// ════════════════════════════════════════════════════════════
process.on('unhandledRejection', (reason) => {
  console.error('Request monitoring error (unhandled rejection):', reason);
});
process.on('uncaughtException', (err) => {
  console.error('Request monitoring error (uncaught exception):', err.message);
});

startRequestMonitor();

// ════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 7860;
app.listen(PORT, () => console.log(`Wevlo Push Server running on port ${PORT}`));
