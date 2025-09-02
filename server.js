const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
app.use(express.json());

// MySQL connection
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'password',
  database: process.env.DB_NAME || 'ecommerce',
  port: process.env.DB_PORT || 3306
};

let db;

// Initialize database
async function initDB() {
  try {
    db = await mysql.createConnection(dbConfig);
    
    // Create users table
    await db.execute(`
      CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
    
    console.log('Database connected and initialized');
  } catch (error) {
    console.error('Database connection failed:', error);
    // Fallback to mock data
    console.log('Using mock database');
  }
}

initDB();

// Routes
app.post('/register', async (req, res) => {
  const { email, password, name } = req.body;
  
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    
    if (db) {
      const [result] = await db.execute(
        'INSERT INTO users (email, password, name) VALUES (?, ?, ?)',
        [email, hashedPassword, name]
      );
      res.status(201).json({ id: result.insertId, email, name });
    } else {
      // Fallback to mock
      const user = { id: Date.now(), email, name };
      res.status(201).json(user);
    }
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      res.status(400).json({ error: 'Email already exists' });
    } else {
      res.status(500).json({ error: 'Registration failed' });
    }
  }
});

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    let user;
    
    if (db) {
      const [rows] = await db.execute(
        'SELECT * FROM users WHERE email = ?',
        [email]
      );
      user = rows[0];
    }
    
    if (!user || !await bcrypt.compare(password, user.password)) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user.id }, 'secret', { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
  } catch (error) {
    res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/profile/:id', async (req, res) => {
  try {
    if (db) {
      const [rows] = await db.execute(
        'SELECT id, email, name FROM users WHERE id = ?',
        [req.params.id]
      );
      
      if (rows.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      res.json(rows[0]);
    } else {
      res.status(503).json({ error: 'Database unavailable' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.listen(3001, () => console.log('User Service running on port 3001'));