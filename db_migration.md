CREATE TABLE ship_station_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key VARCHAR(100) NOT NULL,
    api_secret VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE shippo_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE woo_commerce_credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key VARCHAR(100) NOT NULL,
    api_secret VARCHAR(100) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 0
);



ALTER TABLE ship_station_credentials ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE shippo_credentials ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT 0;
ALTER TABLE woo_commerce_credentials ADD COLUMN enabled BOOLEAN NOT NULL DEFAULT 0;