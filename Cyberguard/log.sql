CREATE TABLE users(
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    name TEXT NOT NULL,
    hash TEXT NOT NULL
    date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE passwords(
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    link TEXT ,
    password TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);