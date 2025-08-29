-- MARIA DB syntax

-- You will need to be running as a user that can create a database and TABLESPACE
-- you do not need to be the Go program user (actually, you probably should not be) since 
-- the go program user should have limited abilities that only include
-- CRUD on the existing tables in the existing database

-- Create the database
CREATE DATABASE gemini_pwd;

-- Select the new database to use it
USE gemini_pwd;

--- Create the database
CREATE DATABASE IF NOT EXISTS gemini_pwd;

-- Select the new database to use it
USE gemini_pwd;

-- Create the users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    is_admin TINYINT(1) NOT NULL DEFAULT 0
);

-- Create the passwords table
CREATE TABLE IF NOT EXISTS passwords (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    service_name VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    password_text TEXT NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create the tags table
CREATE TABLE IF NOT EXISTS tags (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    user_id INT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_tag (user_id, name)
);

-- Create the cross-reference table for passwords and tags
CREATE TABLE IF NOT EXISTS password_tags (
    password_id INT NOT NULL,
    tag_id INT NOT NULL,
    PRIMARY KEY (password_id, tag_id),
    FOREIGN KEY (password_id) REFERENCES passwords(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);

-- Create the password_entries table
CREATE TABLE IF NOT EXISTS password_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    site TEXT NOT NULL,
    username TEXT NOT NULL,
    password_encrypted BLOB,
    notes_encrypted BLOB,
    salt BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create the entry_tags table
CREATE TABLE IF NOT EXISTS entry_tags (
    password_entry_id INT NOT NULL,
    tag_id INT NOT NULL,
    PRIMARY KEY (password_entry_id, tag_id),
    FOREIGN KEY (password_entry_id) REFERENCES password_entries(id) ON DELETE CASCADE,
    FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
);