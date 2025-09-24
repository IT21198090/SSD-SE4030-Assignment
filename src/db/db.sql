-- db.sql  (secure, corrected)
-- NOTE: Run this on a fresh DB (or migrate carefully if you already have data).

-- FIX: Explicit charset/collation for safety & consistency
CREATE DATABASE IF NOT EXISTS hospital
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE hospital;

-- FIX: Use proper INT + AUTO_INCREMENT + NOT NULL + PRIMARY KEY syntax
-- FIX: Use appropriate data types (e.g., DATE for dates instead of VARCHAR)
-- FIX: Add NOT NULL constraints where reasonable
-- FIX: Add indexes/uniques for IDs where appropriate
CREATE TABLE IF NOT EXISTS appointment (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    surname VARCHAR(255) NOT NULL,
    id_number VARCHAR(50) NOT NULL,
    city VARCHAR(100) NOT NULL,
    department VARCHAR(100) NOT NULL,
    date DATE NOT NULL,                  -- FIX: use DATE not VARCHAR
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE INDEX idx_appointment_id_number ON appointment (id_number);

-- FIX: Secure users table: store only a password hash (bcrypt/argon2) not plaintext
-- FIX: Make username unique; widen field to handle emails if needed
CREATE TABLE IF NOT EXISTS users (
    id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL UNIQUE,   -- FIX: unique username
    password_hash VARCHAR(255) NOT NULL, -- FIX: no plaintext password
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- IMPORTANT:
-- Do NOT insert a weak default user like ('Eren', '123').
-- Create users via a secure PHP flow that uses password_hash() (see login notes).
