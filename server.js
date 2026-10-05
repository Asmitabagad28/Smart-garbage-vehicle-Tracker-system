require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());

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

// ---------- helpers: UI value <-> DB value ----------
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

const wrap = (fn) => (req, res, next) => fn(req, res, next).catch(next);

// ---------- API ----------

// Vehicles with their latest tracking position and ETA
app.get('/api/vehicles', wrap(async (req, res) => {
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

// List complaints (optional ?status=pending|assigned|in_progress|resolved|rejected)
app.get('/api/complaints', wrap(async (req, res) => {
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

// File a complaint (multipart form, optional photo)
app.post('/api/complaints', upload.single('photo'), wrap(async (req, res) => {
  const name = (req.body.citizen_name || 'Anonymous').trim().slice(0, 100);
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

    // The form has no login, so reuse (or create) a citizen by name
    const [existing] = await conn.query(
      'SELECT CitizenID FROM Citizen WHERE Name = ? AND Email IS NULL LIMIT 1', [name]);
    let citizenId;
    if (existing.length) {
      citizenId = existing[0].CitizenID;
    } else {
      const [ins] = await conn.query('INSERT INTO Citizen (Name) VALUES (?)', [name]);
      citizenId = ins.insertId;
    }

    const lat = parseFloat(req.body.latitude);
    const lng = parseFloat(req.body.longitude);
    const [result] = await conn.query(
      `INSERT INTO Complaint (CitizenID, LocationID, Description, Priority, Latitude, Longitude)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [citizenId, loc.LocationID, description, severity,
        Number.isFinite(lat) ? lat : loc.Latitude,
        Number.isFinite(lng) ? lng : loc.Longitude]);
    const complaintId = result.insertId;
    const code = `CC-${String(complaintId).padStart(4, '0')}`;

    if (req.file) {
      await conn.query(
        'INSERT INTO Complaint_Media (ComplaintID, FilePath, FileType, Caption) VALUES (?, ?, ?, ?)',
        [complaintId, `/uploads/${req.file.filename}`, req.file.mimetype, req.file.originalname]);
    }

    await conn.query(
      'INSERT INTO Notification (CitizenID, Title, Message, Type) VALUES (?, ?, ?, ?)',
      [citizenId, `Complaint ${code} received`, `Your complaint ${code} for ${area} has been registered.`, 'Complaint']);

    await conn.commit();
    res.status(201).json({ id: complaintId, complaint_code: code });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// Update a complaint's status (used by "Mark resolved")
app.patch('/api/complaints/:id', wrap(async (req, res) => {
  const dbStatus = STATUS_TO_DB[req.body.status];
  if (!dbStatus) return res.status(400).json({ message: 'Invalid status' });

  const [result] = await pool.query(
    `UPDATE Complaint
     SET Status = ?, ResolvedDate = IF(? = 'Resolved', NOW(), NULL)
     WHERE ComplaintID = ?`,
    [dbStatus, dbStatus, req.params.id]);
  if (result.affectedRows === 0) return res.status(404).json({ message: 'Complaint not found' });

  if (dbStatus === 'Resolved') {
    const code = `CC-${String(req.params.id).padStart(4, '0')}`;
    await pool.query(
      `INSERT INTO Notification (CitizenID, Title, Message, Type)
       SELECT CitizenID, ?, ?, 'Complaint' FROM Complaint WHERE ComplaintID = ?`,
      [`Complaint ${code} resolved`, `Your complaint ${code} has been marked as resolved.`, req.params.id]);
  }
  res.json({ ok: true });
}));

// Dashboard numbers
app.get('/api/dashboard/summary', wrap(async (req, res) => {
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

// ---------- static files ----------
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static(path.join(__dirname, 'public')));   // index.html + style.css live here

// ---------- errors ----------
app.use((err, req, res, next) => {
  console.error(err);
  const isUserError = err instanceof multer.MulterError || /image files/.test(err.message);
  res.status(isUserError ? 400 : 500).json({
    message: isUserError ? err.message : 'Something went wrong on the server',
  });
});

const PORT = Number(process.env.PORT || 3000);
app.listen(PORT, () => console.log(`CityClean running at http://localhost:${PORT}`));
