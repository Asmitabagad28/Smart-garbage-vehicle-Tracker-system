-- =====================================================
-- CityClean: Smart Garbage Collection & Complaint Tracking
-- MySQL 8.x schema (ER diagram + small changes for index.html)
--
-- Changes vs the first script:
--   * Citizen.Phone / Email / Password are nullable (the report form only asks for a name)
--   * Complaint.Status also allows 'Assigned' (the UI has an "Assigned" filter)
--   * Vehicle_Tracking.EtaMinutes added (the live map shows "X min" per vehicle)
-- =====================================================

DROP DATABASE IF EXISTS smart_garbage_db;
CREATE DATABASE smart_garbage_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE smart_garbage_db;

CREATE TABLE Citizen (
    CitizenID        INT AUTO_INCREMENT PRIMARY KEY,
    Name             VARCHAR(100) NOT NULL,
    Phone            VARCHAR(15)  NULL,
    Email            VARCHAR(120) NULL UNIQUE,
    Password         VARCHAR(255) NULL,              -- store a hash, never plain text
    Address          VARCHAR(255),
    Gender           ENUM('Male','Female','Other'),
    RegistrationDate DATE NOT NULL DEFAULT (CURRENT_DATE),
    Role             VARCHAR(20) NOT NULL DEFAULT 'Citizen'
) ENGINE=InnoDB;

CREATE TABLE Location (
    LocationID INT AUTO_INCREMENT PRIMARY KEY,
    AreaName   VARCHAR(100) NOT NULL UNIQUE,
    Ward       VARCHAR(50),
    Address    VARCHAR(255),
    Latitude   DECIMAL(10,7),
    Longitude  DECIMAL(10,7),
    Zone       VARCHAR(50)
) ENGINE=InnoDB;

CREATE TABLE Route (
    RouteID         INT AUTO_INCREMENT PRIMARY KEY,
    RouteName       VARCHAR(100) NOT NULL,
    StartLocationID INT NOT NULL,
    EndLocationID   INT NOT NULL,
    StartTime       TIME,
    EndTime         TIME,
    LocationID      INT NOT NULL,                    -- area this route covers
    CONSTRAINT fk_route_start  FOREIGN KEY (StartLocationID) REFERENCES Location(LocationID),
    CONSTRAINT fk_route_end    FOREIGN KEY (EndLocationID)   REFERENCES Location(LocationID),
    CONSTRAINT fk_route_covers FOREIGN KEY (LocationID)      REFERENCES Location(LocationID)
) ENGINE=InnoDB;

CREATE TABLE Vehicle (
    VehicleID     INT AUTO_INCREMENT PRIMARY KEY,
    VehicleNumber VARCHAR(20) NOT NULL UNIQUE,
    VehicleType   VARCHAR(50),
    Capacity      DECIMAL(8,2),
    Status        ENUM('Active','Inactive') NOT NULL DEFAULT 'Active',
    RouteID       INT UNIQUE,                        -- 1 route : 1 vehicle
    CONSTRAINT fk_vehicle_route FOREIGN KEY (RouteID) REFERENCES Route(RouteID) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE Driver (
    DriverID      INT AUTO_INCREMENT PRIMARY KEY,
    Name          VARCHAR(100) NOT NULL,
    Phone         VARCHAR(15),
    Email         VARCHAR(120),
    LicenseNumber VARCHAR(30) NOT NULL UNIQUE,
    Status        VARCHAR(20) DEFAULT 'Available',
    VehicleID     INT,
    CONSTRAINT fk_driver_vehicle FOREIGN KEY (VehicleID) REFERENCES Vehicle(VehicleID) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE Complaint (
    ComplaintID   INT AUTO_INCREMENT PRIMARY KEY,
    CitizenID     INT NOT NULL,
    LocationID    INT NOT NULL,
    ComplaintDate DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    Description   TEXT NOT NULL,
    Status        ENUM('Pending','Assigned','In Progress','Resolved','Rejected') NOT NULL DEFAULT 'Pending',
    Priority      ENUM('Low','Medium','High') NOT NULL DEFAULT 'Medium',
    Latitude      DECIMAL(10,7),
    Longitude     DECIMAL(10,7),
    ResolvedDate  DATETIME NULL,
    CONSTRAINT fk_complaint_citizen  FOREIGN KEY (CitizenID)  REFERENCES Citizen(CitizenID) ON DELETE CASCADE,
    CONSTRAINT fk_complaint_location FOREIGN KEY (LocationID) REFERENCES Location(LocationID)
) ENGINE=InnoDB;

CREATE TABLE Complaint_Media (
    MediaID     INT AUTO_INCREMENT PRIMARY KEY,
    ComplaintID INT NOT NULL,
    FilePath    VARCHAR(255) NOT NULL,
    FileType    VARCHAR(50),
    UploadDate  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    Caption     VARCHAR(255),
    CONSTRAINT fk_media_complaint FOREIGN KEY (ComplaintID) REFERENCES Complaint(ComplaintID) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE Notification (
    NotificationID INT AUTO_INCREMENT PRIMARY KEY,
    CitizenID      INT NOT NULL,
    Title          VARCHAR(150) NOT NULL,
    Message        TEXT,
    Type           VARCHAR(50),
    DateTime       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    IsRead         ENUM('Yes','No') NOT NULL DEFAULT 'No',
    CONSTRAINT fk_notification_citizen FOREIGN KEY (CitizenID) REFERENCES Citizen(CitizenID) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE Vehicle_Feedback (
    FeedbackID     INT AUTO_INCREMENT PRIMARY KEY,
    NotificationID INT NOT NULL,
    Rating         TINYINT NOT NULL,
    Comments       TEXT,
    FeedbackDate   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_rating CHECK (Rating BETWEEN 1 AND 5),
    CONSTRAINT fk_feedback_notification FOREIGN KEY (NotificationID) REFERENCES Notification(NotificationID) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE Vehicle_Tracking (
    TrackingID INT AUTO_INCREMENT PRIMARY KEY,
    DriverID   INT NOT NULL,
    Latitude   DECIMAL(10,7) NOT NULL,
    Longitude  DECIMAL(10,7) NOT NULL,
    Timestamp  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    Speed      DECIMAL(5,2),
    Status     VARCHAR(30),
    EtaMinutes INT,
    CONSTRAINT fk_tracking_driver FOREIGN KEY (DriverID) REFERENCES Driver(DriverID) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE INDEX idx_complaint_status  ON Complaint(Status, Priority);
CREATE INDEX idx_tracking_time     ON Vehicle_Tracking(DriverID, Timestamp);
CREATE INDEX idx_notification_read ON Notification(CitizenID, IsRead);

-- =====================================================
-- SEED DATA (coordinates are approximate)
-- Area names must match the dropdown in index.html
-- =====================================================
INSERT INTO Location (AreaName, Ward, Address, Latitude, Longitude, Zone) VALUES
('Wadala Truck Terminal', 'F/North', 'Wadala Truck Terminal, Mumbai', 19.0178000, 72.8706000, 'Zone 2'),
('Kidwai Nagar',          'F/North', 'Kidwai Nagar, Wadala, Mumbai', 19.0262000, 72.8581000, 'Zone 2'),
('Antop Hill',            'F/North', 'Antop Hill, Mumbai',           19.0245000, 72.8651000, 'Zone 2'),
('Bhakti Park',           'F/North', 'Bhakti Park, Wadala, Mumbai',  19.0300000, 72.8630000, 'Zone 2');

INSERT INTO Route (RouteName, StartLocationID, EndLocationID, StartTime, EndTime, LocationID) VALUES
('Wadala Terminal Loop', 1, 2, '06:00:00', '10:00:00', 1),
('Kidwai Nagar Route',   2, 3, '06:30:00', '10:30:00', 2),
('Antop Hill Route',     3, 4, '07:00:00', '11:00:00', 3),
('Bhakti Park Route',    4, 3, '07:30:00', '11:30:00', 4);

INSERT INTO Vehicle (VehicleNumber, VehicleType, Capacity, Status, RouteID) VALUES
('MH01AB1234', 'Compactor Truck', 5.00, 'Active', 1),
('MH01CD5678', 'Compactor Truck', 5.00, 'Active', 2),
('MH02EF9012', 'Tipper',          3.50, 'Active', 3),
('MH03GH3456', 'Mini Truck',      2.00, 'Active', 4);

INSERT INTO Driver (Name, Phone, Email, LicenseNumber, Status, VehicleID) VALUES
('Suresh Kale',   '9988776655', 'suresh@example.com', 'MH0120250001234', 'On Duty', 1),
('Imran Shaikh',  '9988776656', 'imran@example.com',  'MH0120250001235', 'On Duty', 2),
('Ganesh Pawar',  '9988776657', 'ganesh@example.com', 'MH0120250001236', 'On Duty', 3),
('Vijay Jadhav',  '9988776658', 'vijay@example.com',  'MH0120250001237', 'On Duty', 4);

INSERT INTO Vehicle_Tracking (DriverID, Latitude, Longitude, Speed, Status, EtaMinutes) VALUES
(1, 19.0180000, 72.8690000, 22.50, 'Moving',  6),
(2, 19.0255000, 72.8590000, 18.00, 'Moving', 14),
(3, 19.0240000, 72.8660000,  0.00, 'Stopped', 28),
(4, 19.0295000, 72.8625000, 25.00, 'Moving',  9);

INSERT INTO Citizen (Name) VALUES ('Asha Patil'), ('Rohan Sharma');

INSERT INTO Complaint (CitizenID, LocationID, Description, Status, Priority, Latitude, Longitude) VALUES
(1, 2, 'Garbage not collected for 3 days near the bus stop.', 'Pending',  'High',   19.0262000, 72.8581000),
(2, 3, 'Overflowing bin outside the school gate.',            'Assigned', 'Medium', 19.0245000, 72.8651000);
