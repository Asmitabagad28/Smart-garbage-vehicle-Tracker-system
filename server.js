require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());

// ---------- config ----------
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  JWT_SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('WARNING: JWT_SECRET is not set in .env. Using a temporary one, so everyone is logged out whenever the server restarts.');
}

// ---------- database ----------
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'smart_garbage_db',
  waitForConnections: true,
  connectionLimit: 10,
});

// ---------- photo uploads ----------
const UPLOAD_DIR = path.join(__dirname, 'uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) =>
      cb(null, `${Date.now()}-${Math.round(Math.random() * 1e6)}${path.extname(file.originalname).toLowerCase()}`),
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) =>
    file.mimetype.startsWith('image/') ? cb(null, true) : cb(new Error('Only image files are allowed')),
});

// ---------- helpers ----------
const STATUS_TO_DB = {
  pending: 'Pending',
  assigned: 'Assigned',
  in_progress: 'In Progress',
  resolved: 'Resolved',
  rejected: 'Rejected',
};
const SEVERITY_TO_DB = { low: 'Low', medium: 'Medium', high: 'High' };

const COMPLAINT_SELECT = `
  SELECT c.ComplaintID                               AS id,
         CONCAT('CC-', LPAD(c.ComplaintID, 4, '0'))  AS complaint_code,
         ci.Name                                     AS citizen_name,
         l.AreaName                                  AS area,
         LOWER(c.Priority)                           AS severity,
         LOWER(REPLACE(c.Status, ' ', '_'))          AS status,
         c.Description                               AS description,
         c.ComplaintDate                             AS created_at
  FROM Complaint c
  JOIN Citizen  ci ON ci.CitizenID = c.CitizenID
  JOIN Location l  ON l.LocationID = c.LocationID`;

const codeFor = (id) => `CC-${String(id).padStart(4, '0')}`;
class InputError extends Error {}
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role });
const signToken = (id) => jwt.sign({ id }, JWT_SECRET, { expiresIn: '7d' });

// ---------- auth middleware ----------
// Reads the "Authorization: Bearer <token>" header and loads the user from the database.
const requireAuth = wrap(async (req, res, next) => {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Please log in' });

  let payload;
  try {
    payload = jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return res.status(401).json({ message: 'Session expired, please log in again' });
  }
  const [rows] = await pool.query(
    'SELECT CitizenID, Name, Email, Role FROM Citizen WHERE CitizenID = ?', [payload.id]);
  if (rows.length === 0) return res.status(401).json({ message: 'Account not found, please log in again' });

  req.user = { id: rows[0].CitizenID, name: rows[0].Name, email: rows[0].Email, role: rows[0].Role };
  next();
});

// Must come AFTER requireAuth. Blocks everyone who is not an admin.
const requireAdmin = (req, res, next) =>
  req.user && req.user.role === 'Admin' ? next() : res.status(403).json({ message: 'Admins only' });

// Very small brute-force guard: 10 failed logins per email+IP per 15 minutes
const failedLogins = new Map();
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILS = 10;
const recentFails = (key) => {
  const list = (failedLogins.get(key) || []).filter((t) => Date.now() - t < LOGIN_WINDOW_MS);
  failedLogins.set(key, list);
  return list;
};

// ---------- auth routes ----------
// Checks the fields shared by citizen and admin sign-up
function readNewAccount(body, minPassword) {
  const name = String(body.name || '').trim().slice(0, 100);
  const email = String(body.email || '').trim().toLowerCase();
  const phone = String(body.phone || '').trim().slice(0, 15) || null;
  const password = String(body.password || '');

  if (name.length < 2) throw new InputError('Please enter your full name');
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 120)
    throw new InputError('Please enter a valid email address');
  if (password.length < minPassword) throw new InputError(`Password must be at least ${minPassword} characters`);
  if (password.length > 72) throw new InputError('Password must be 72 characters or fewer');
  return { name, email, phone, password };
}

async function createAccount(fields, role) {
  const hash = await bcrypt.hash(fields.password, 10);
  try {
    const [result] = await pool.query(
      'INSERT INTO Citizen (Name, Email, Phone, Password, Role) VALUES (?, ?, ?, ?, ?)',
      [fields.name, fields.email, fields.phone, hash, role]);
    return { id: result.insertId, name: fields.name, email: fields.email, role };
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') {
      const dup = new InputError('An account with this email already exists');
      dup.status = 409;
      throw dup;
    }
    throw err;
  }
}

// Citizen sign-up. The role is always 'Citizen', whatever the request says.
app.post('/api/register', wrap(async (req, res) => {
  const user = await createAccount(readNewAccount(req.body || {}, 8), 'Citizen');
  res.status(201).json({ token: signToken(user.id), user: publicUser(user) });
}));

// Admin sign-up: only works for people who know the secret code from .env
const ADMIN_CODE = process.env.ADMIN_REGISTRATION_CODE || '';
const sha256 = (v) => crypto.createHash('sha256').update(String(v)).digest();
const adminCodeMatches = (given) => crypto.timingSafeEqual(sha256(given), sha256(ADMIN_CODE));

app.post('/api/register-admin', wrap(async (req, res) => {
  const body = req.body || {};
  if (!ADMIN_CODE)
    return res.status(403).json({ message: 'Admin registration is turned off. The system owner must set ADMIN_REGISTRATION_CODE in the .env file.' });

  const key = `${req.ip}|admin-code`;
  if (recentFails(key).length >= LOGIN_MAX_FAILS)
    return res.status(429).json({ message: 'Too many wrong codes. Please try again in a few minutes.' });
  if (!adminCodeMatches(body.admin_code || '')) {
    recentFails(key).push(Date.now());
    return res.status(403).json({ message: 'Incorrect admin registration code' });
  }

  const user = await createAccount(readNewAccount(body, 10), 'Admin');
  res.status(201).json({ token: signToken(user.id), user: publicUser(user) });
}));

app.post('/api/login', wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const key = `${req.ip}|${email}`;

  if (recentFails(key).length >= LOGIN_MAX_FAILS)
    return res.status(429).json({ message: 'Too many failed attempts. Please try again in a few minutes.' });

  const [rows] = await pool.query(
    'SELECT CitizenID, Name, Email, Password, Role FROM Citizen WHERE Email = ?', [email]);
  const ok = rows.length > 0 && rows[0].Password && (await bcrypt.compare(password, rows[0].Password));
  if (!ok) {
    recentFails(key).push(Date.now());
    return res.status(401).json({ message: 'Incorrect email or password' });
  }
  failedLogins.delete(key);
  const user = { id: rows[0].CitizenID, name: rows[0].Name, email: rows[0].Email, role: rows[0].Role };
  res.json({ token: signToken(user.id), user: publicUser(user) });
}));

app.get('/api/me', requireAuth, (req, res) => res.json({ user: publicUser(req.user) }));

// ---------- API for any logged-in user ----------

// Vehicles with their latest tracking position and ETA
app.get('/api/vehicles', requireAuth, wrap(async (req, res) => {
  const [rows] = await pool.query(`
    SELECT v.VehicleID     AS id,
           v.VehicleNumber AS vehicle_number,
           COALESCE(l.AreaName, 'Unassigned') AS area,
           t.Latitude      AS latitude,
           t.Longitude     AS longitude,
           t.EtaMinutes    AS eta_minutes
    FROM Vehicle v
    LEFT JOIN Route    r ON r.RouteID = v.RouteID
    LEFT JOIN Location l ON l.LocationID = r.LocationID
    LEFT JOIN Vehicle_Tracking t ON t.TrackingID = (
        SELECT t2.TrackingID
        FROM Vehicle_Tracking t2
        JOIN Driver d2 ON d2.DriverID = t2.DriverID
        WHERE d2.VehicleID = v.VehicleID
        ORDER BY t2.Timestamp DESC, t2.TrackingID DESC
        LIMIT 1)
    WHERE v.Status = 'Active'
    ORDER BY t.EtaMinutes IS NULL, t.EtaMinutes`);
  res.json(rows);
}));

// MY complaints only (optional ?status=...)
app.get('/api/complaints', requireAuth, wrap(async (req, res) => {
  const params = [req.user.id];
  let where = ' WHERE c.CitizenID = ?';
  if (req.query.status) {
    const dbStatus = STATUS_TO_DB[req.query.status];
    if (!dbStatus) return res.status(400).json({ message: 'Invalid status filter' });
    where += ' AND c.Status = ?';
    params.push(dbStatus);
  }
  const [rows] = await pool.query(
    `${COMPLAINT_SELECT}${where} ORDER BY c.ComplaintDate DESC, c.ComplaintID DESC`, params);
  res.json(rows);
}));

// File a complaint as the logged-in user (multipart form, optional photo)
app.post('/api/complaints', requireAuth, upload.single('photo'), wrap(async (req, res) => {
  const area = (req.body.area || '').trim();
  const description = (req.body.description || '').trim();
  const severity = SEVERITY_TO_DB[(req.body.severity || 'medium').toLowerCase()];

  if (!area) return res.status(400).json({ message: 'Please select an area' });
  if (!description) return res.status(400).json({ message: 'Please describe the issue' });
  if (!severity) return res.status(400).json({ message: 'Invalid severity' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [locs] = await conn.query(
      'SELECT LocationID, Latitude, Longitude FROM Location WHERE AreaName = ?', [area]);
    if (locs.length === 0) {
      await conn.rollback();
      return res.status(400).json({ message: 'Unknown area' });
    }
    const loc = locs[0];

    const lat = parseFloat(req.body.latitude);
    const lng = parseFloat(req.body.longitude);
    const [result] = await conn.query(
      `INSERT INTO Complaint (CitizenID, LocationID, Description, Priority, Latitude, Longitude)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [req.user.id, loc.LocationID, description, severity,
        Number.isFinite(lat) ? lat : loc.Latitude,
        Number.isFinite(lng) ? lng : loc.Longitude]);
    const complaintId = result.insertId;
    const code = codeFor(complaintId);

    if (req.file) {
      await conn.query(
        'INSERT INTO Complaint_Media (ComplaintID, FilePath, FileType, Caption) VALUES (?, ?, ?, ?)',
        [complaintId, `/uploads/${req.file.filename}`, req.file.mimetype, req.file.originalname]);
    }

    await conn.query(
      'INSERT INTO Notification (CitizenID, Title, Message, Type) VALUES (?, ?, ?, ?)',
      [req.user.id, `Complaint ${code} received`, `Your complaint ${code} for ${area} has been registered.`, 'Complaint']);

    await conn.commit();
    res.status(201).json({ id: complaintId, complaint_code: code });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// MY notifications
app.get('/api/notifications', requireAuth, wrap(async (req, res) => {
  const [rows] = await pool.query(
    `SELECT NotificationID AS id, Title AS title, Message AS message, Type AS type,
            \`DateTime\` AS created_at, IsRead AS is_read
     FROM Notification
     WHERE CitizenID = ?
     ORDER BY \`DateTime\` DESC, NotificationID DESC
     LIMIT 50`, [req.user.id]);
  const icon = { Resolved: 'check', Update: 'truck', Complaint: 'camera' };
  res.json(rows.map((r) => ({ ...r, ic: icon[r.type] || 'camera' })));
}));

// ---------- ADMIN-ONLY API ----------

// All complaints from everyone
app.get('/api/admin/complaints', requireAuth, requireAdmin, wrap(async (req, res) => {
  const params = [];
  let where = '';
  if (req.query.status) {
    const dbStatus = STATUS_TO_DB[req.query.status];
    if (!dbStatus) return res.status(400).json({ message: 'Invalid status filter' });
    where = ' WHERE c.Status = ?';
    params.push(dbStatus);
  }
  const [rows] = await pool.query(
    `${COMPLAINT_SELECT}${where} ORDER BY c.ComplaintDate DESC, c.ComplaintID DESC`, params);
  res.json(rows);
}));

// Change a complaint's status and notify the citizen who reported it
app.patch('/api/admin/complaints/:id', requireAuth, requireAdmin, wrap(async (req, res) => {
  const dbStatus = STATUS_TO_DB[req.body.status];
  if (!dbStatus) return res.status(400).json({ message: 'Invalid status' });

  const [found] = await pool.query('SELECT CitizenID FROM Complaint WHERE ComplaintID = ?', [req.params.id]);
  if (found.length === 0) return res.status(404).json({ message: 'Complaint not found' });

  await pool.query(
    `UPDATE Complaint
     SET Status = ?, ResolvedDate = IF(? = 'Resolved', NOW(), NULL)
     WHERE ComplaintID = ?`,
    [dbStatus, dbStatus, req.params.id]);

  const code = codeFor(req.params.id);
  const resolved = dbStatus === 'Resolved';
  await pool.query(
    'INSERT INTO Notification (CitizenID, Title, Message, Type) VALUES (?, ?, ?, ?)',
    [found[0].CitizenID,
      resolved ? `Complaint ${code} resolved` : `Complaint ${code} is now ${dbStatus}`,
      `The status of your complaint ${code} was changed to ${dbStatus}.`,
      resolved ? 'Resolved' : 'Update']);
  res.json({ ok: true });
}));

// Dashboard numbers
app.get('/api/admin/summary', requireAuth, requireAdmin, wrap(async (req, res) => {
  const [[totals]] = await pool.query(`
    SELECT COUNT(*) AS total,
           SUM(Status = 'Resolved')                     AS resolved,
           SUM(Status = 'Pending')                      AS pending,
           SUM(Status IN ('Assigned', 'In Progress'))   AS in_progress
    FROM Complaint`);
  const [byArea] = await pool.query(`
    SELECT l.AreaName AS area, COUNT(c.ComplaintID) AS count
    FROM Location l
    JOIN Complaint c ON c.LocationID = l.LocationID
    GROUP BY l.LocationID, l.AreaName
    ORDER BY count DESC`);
  res.json({
    total_complaints: Number(totals.total),
    resolved: Number(totals.resolved || 0),
    pending: Number(totals.pending || 0),
    in_progress: Number(totals.in_progress || 0),
    complaints_by_area: byArea.map((r) => ({ area: r.area, count: Number(r.count) })),
  });
}));

// ---------- ADMIN: vehicle management ----------

const blank = (v) => v === undefined || v === null || String(v).trim() === '';
const text = (v, max) => String(v === undefined || v === null ? '' : v).trim().slice(0, max);

function friendlyDuplicate(err) {
  if (/LicenseNumber/i.test(err.message)) return 'A driver with this license number already exists';
  if (/VehicleNumber/i.test(err.message)) return 'A vehicle with this number already exists';
  return 'That value already exists';
}

// Checks one vehicle (from the form or one CSV row) and returns clean values.
async function parseVehicleInput(conn, raw) {
  const number = text(raw.vehicle_number, 40).toUpperCase().replace(/\s+/g, '');
  if (!/^[A-Z0-9-]{4,20}$/.test(number))
    throw new InputError('Vehicle number must be 4-20 letters or digits, for example MH01AB1234');

  let capacity = null;
  if (!blank(raw.capacity)) {
    capacity = Number(raw.capacity);
    if (!Number.isFinite(capacity) || capacity < 0 || capacity > 999999.99)
      throw new InputError('Capacity must be a positive number');
  }

  let status = 'Active';
  if (!blank(raw.status)) {
    const st = String(raw.status).trim().toLowerCase();
    if (st === 'active') status = 'Active';
    else if (st === 'inactive') status = 'Inactive';
    else throw new InputError('Status must be Active or Inactive');
  }

  let location = null;
  if (!blank(raw.location_id)) {
    const id = Number(raw.location_id);
    const [rows] = Number.isInteger(id)
      ? await conn.query('SELECT LocationID, AreaName, Latitude, Longitude FROM Location WHERE LocationID = ?', [id])
      : [[]];
    if (rows.length === 0) throw new InputError('Unknown area');
    location = rows[0];
  } else if (!blank(raw.area)) {
    const name = text(raw.area, 100);
    const [rows] = await conn.query(
      'SELECT LocationID, AreaName, Latitude, Longitude FROM Location WHERE AreaName = ?', [name]);
    if (rows.length === 0) throw new InputError(`Unknown area "${name}"`);
    location = rows[0];
  }

  const dName = text(raw.driver_name, 100);
  const dPhone = text(raw.driver_phone, 15);
  const dLicense = text(raw.license_number, 30).toUpperCase();
  let driver = null;
  if (dName || dPhone || dLicense) {
    if (!dName || !dLicense) throw new InputError('A driver needs both a name and a license number');
    driver = { name: dName, phone: dPhone || null, license: dLicense };
  }

  let lat = null;
  let lng = null;
  const hasLat = !blank(raw.latitude);
  const hasLng = !blank(raw.longitude);
  if (hasLat !== hasLng) throw new InputError('Enter both latitude and longitude, or leave both empty');
  if (hasLat) {
    lat = Number(raw.latitude);
    lng = Number(raw.longitude);
    if (!(lat >= -90 && lat <= 90) || !(lng >= -180 && lng <= 180))
      throw new InputError('Latitude or longitude is out of range');
  }

  let eta = null;
  if (!blank(raw.eta_minutes)) {
    eta = Number(raw.eta_minutes);
    if (!Number.isInteger(eta) || eta < 0 || eta > 1440)
      throw new InputError('ETA must be a whole number of minutes (0-1440)');
  }

  if ((lat !== null || eta !== null) && !driver)
    throw new InputError('Add a driver to track this vehicle\'s position or ETA');

  return { number, type: text(raw.vehicle_type, 50) || null, capacity, status, location, driver, lat, lng, eta };
}

// Saves one vehicle (+ its route and driver) in a single transaction.
async function saveVehicle(raw) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const d = await parseVehicleInput(conn, raw);

    let routeId = null;
    if (d.location) {
      const [r] = await conn.query(
        'INSERT INTO Route (RouteName, StartLocationID, EndLocationID, LocationID) VALUES (?, ?, ?, ?)',
        [`${d.location.AreaName} - ${d.number}`.slice(0, 100), d.location.LocationID, d.location.LocationID, d.location.LocationID]);
      routeId = r.insertId;
    }

    const [v] = await conn.query(
      'INSERT INTO Vehicle (VehicleNumber, VehicleType, Capacity, Status, RouteID) VALUES (?, ?, ?, ?, ?)',
      [d.number, d.type, d.capacity, d.status, routeId]);

    if (d.driver) {
      const [dr] = await conn.query(
        'INSERT INTO Driver (Name, Phone, LicenseNumber, Status, VehicleID) VALUES (?, ?, ?, ?, ?)',
        [d.driver.name, d.driver.phone, d.driver.license, 'On Duty', v.insertId]);

      // No position given? Start the vehicle at the centre of its area so it shows on the map.
      let lat = d.lat;
      let lng = d.lng;
      if (lat === null && d.location && d.location.Latitude !== null) {
        lat = Number(d.location.Latitude);
        lng = Number(d.location.Longitude);
      }
      if (lat !== null) {
        await conn.query(
          'INSERT INTO Vehicle_Tracking (DriverID, Latitude, Longitude, Speed, Status, EtaMinutes) VALUES (?, ?, ?, 0, ?, ?)',
          [dr.insertId, lat, lng, 'Stopped', d.eta]);
      }
    }

    await conn.commit();
    return v.insertId;
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}

// Areas for the "Area covered" dropdown
app.get('/api/admin/locations', requireAuth, requireAdmin, wrap(async (req, res) => {
  const [rows] = await pool.query('SELECT LocationID AS id, AreaName AS area FROM Location ORDER BY AreaName');
  res.json(rows);
}));

// All vehicles with driver, area and latest position
app.get('/api/admin/vehicles', requireAuth, requireAdmin, wrap(async (req, res) => {
  const [rows] = await pool.query(`
    SELECT v.VehicleID AS id, v.VehicleNumber AS vehicle_number, v.VehicleType AS vehicle_type,
           v.Capacity AS capacity, v.Status AS status, l.AreaName AS area,
           d.Name AS driver_name, d.Phone AS driver_phone, d.LicenseNumber AS license_number,
           t.Latitude AS latitude, t.Longitude AS longitude, t.EtaMinutes AS eta_minutes
    FROM Vehicle v
    LEFT JOIN Route    r ON r.RouteID = v.RouteID
    LEFT JOIN Location l ON l.LocationID = r.LocationID
    LEFT JOIN Driver   d ON d.DriverID = (SELECT MIN(d2.DriverID) FROM Driver d2 WHERE d2.VehicleID = v.VehicleID)
    LEFT JOIN Vehicle_Tracking t ON t.TrackingID = (
        SELECT t2.TrackingID
        FROM Vehicle_Tracking t2
        JOIN Driver d3 ON d3.DriverID = t2.DriverID
        WHERE d3.VehicleID = v.VehicleID
        ORDER BY t2.Timestamp DESC, t2.TrackingID DESC
        LIMIT 1)
    ORDER BY v.VehicleNumber`);
  res.json(rows);
}));

// Add one vehicle
app.post('/api/admin/vehicles', requireAuth, requireAdmin, wrap(async (req, res) => {
  try {
    const id = await saveVehicle(req.body || {});
    res.status(201).json({ id });
  } catch (err) {
    if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: friendlyDuplicate(err) });
    throw err;
  }
}));

// Add many vehicles at once (rows come from a CSV file read in the browser)
app.post('/api/admin/vehicles/bulk', requireAuth, requireAdmin, wrap(async (req, res) => {
  const rows = Array.isArray(req.body.rows) ? req.body.rows : null;
  if (!rows || rows.length === 0) throw new InputError('The file has no vehicle rows');
  if (rows.length > 200) throw new InputError('Please import at most 200 vehicles at a time');

  let created = 0;
  const errors = [];
  for (let i = 0; i < rows.length; i++) {
    try {
      await saveVehicle(rows[i] || {});
      created++;
    } catch (err) {
      if (err instanceof InputError) errors.push({ row: i + 2, message: err.message });   // +2: header is row 1
      else if (err.code === 'ER_DUP_ENTRY') errors.push({ row: i + 2, message: friendlyDuplicate(err) });
      else throw err;
    }
  }
  res.json({ created, errors });
}));

// Change a vehicle's status and/or record a new position + ETA
app.patch('/api/admin/vehicles/:id', requireAuth, requireAdmin, wrap(async (req, res) => {
  const [found] = await pool.query('SELECT VehicleID FROM Vehicle WHERE VehicleID = ?', [req.params.id]);
  if (found.length === 0) return res.status(404).json({ message: 'Vehicle not found' });

  const body = req.body || {};
  if (!blank(body.status)) {
    const st = String(body.status).trim().toLowerCase();
    if (st !== 'active' && st !== 'inactive') return res.status(400).json({ message: 'Status must be Active or Inactive' });
    await pool.query('UPDATE Vehicle SET Status = ? WHERE VehicleID = ?',
      [st === 'active' ? 'Active' : 'Inactive', req.params.id]);
  }

  if (!blank(body.latitude) || !blank(body.longitude)) {
    const lat = Number(body.latitude);
    const lng = Number(body.longitude);
    if (blank(body.latitude) || blank(body.longitude) || !(lat >= -90 && lat <= 90) || !(lng >= -180 && lng <= 180))
      throw new InputError('Enter a valid latitude and longitude');
    let eta = null;
    if (!blank(body.eta_minutes)) {
      eta = Number(body.eta_minutes);
      if (!Number.isInteger(eta) || eta < 0 || eta > 1440) throw new InputError('ETA must be a whole number of minutes (0-1440)');
    }
    const [drivers] = await pool.query(
      'SELECT DriverID FROM Driver WHERE VehicleID = ? ORDER BY DriverID LIMIT 1', [req.params.id]);
    if (drivers.length === 0) throw new InputError('This vehicle has no driver, so its position cannot be tracked');
    await pool.query(
      'INSERT INTO Vehicle_Tracking (DriverID, Latitude, Longitude, Speed, Status, EtaMinutes) VALUES (?, ?, ?, 0, ?, ?)',
      [drivers[0].DriverID, lat, lng, 'Updated', eta]);
  }
  res.json({ ok: true });
}));

// Remove a vehicle together with its drivers and its route
app.delete('/api/admin/vehicles/:id', requireAuth, requireAdmin, wrap(async (req, res) => {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [found] = await conn.query('SELECT RouteID FROM Vehicle WHERE VehicleID = ?', [req.params.id]);
    if (found.length === 0) {
      await conn.rollback();
      return res.status(404).json({ message: 'Vehicle not found' });
    }
    await conn.query('DELETE FROM Driver WHERE VehicleID = ?', [req.params.id]);   // tracking rows go with them
    await conn.query('DELETE FROM Vehicle WHERE VehicleID = ?', [req.params.id]);
    if (found[0].RouteID) await conn.query('DELETE FROM Route WHERE RouteID = ?', [found[0].RouteID]);
    await conn.commit();
    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// Unknown /api routes get JSON, not an HTML page
app.use('/api', (req, res) => res.status(404).json({ message: 'Not found' }));

// ---------- static files ----------
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static(path.join(__dirname, 'public')));   // index.html + style.css live here

// ---------- errors ----------
app.use((err, req, res, next) => {
  const isUserError = err instanceof InputError || err instanceof multer.MulterError || /image files/.test(err.message);
  if (!isUserError) console.error(err);   // only real server problems are logged
  res.status(isUserError ? (err.status || 400) : 500).json({
    message: isUserError ? err.message : 'Something went wrong on the server',
  });
});

// ---------- first admin account ----------
// If the database has no admin yet, create one from ADMIN_EMAIL / ADMIN_PASSWORD in .env
async function ensureAdmin() {
  const [rows] = await pool.query("SELECT CitizenID FROM Citizen WHERE Role = 'Admin' LIMIT 1");
  if (rows.length) return;
  const email = String(process.env.ADMIN_EMAIL || 'admin@cityclean.com').trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD || 'ChangeMe@123';
  const hash = await bcrypt.hash(password, 10);
  await pool.query(
    "INSERT INTO Citizen (Name, Email, Password, Role) VALUES ('Administrator', ?, ?, 'Admin')", [email, hash]);
  console.log(`Created admin account: ${email}`);
  if (!process.env.ADMIN_PASSWORD) {
    console.warn('WARNING: using the default admin password. Set ADMIN_EMAIL and ADMIN_PASSWORD in .env and change it.');
  }
}

const PORT = Number(process.env.PORT || 3000);
ensureAdmin()
  .catch((err) => console.error('Could not create the admin account:', err.message))
  .finally(() => app.listen(PORT, () => console.log(`CityClean running at http://localhost:${PORT}`)));
