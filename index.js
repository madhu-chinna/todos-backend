const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const { open } = require('sqlite');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');


const app = express();
const PORT = 3008;
const JWT_SECRET = 'TODOS';

const dbPath = path.join(__dirname, 'todo.db');
let db = null;

// Enable CORS for all routes
app.use(cors());

// Middleware to parse JSON bodies
app.use(express.json());

// Initialize Database and Server
const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });

    // Create tables after establishing DB connection
    await createTables();

    app.listen(PORT, () => {
      console.log(`Server Running at http://localhost:${PORT}/`);
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();


// Helper Function to Create Tables if not exists
const createTables = async () => {
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT,
      email TEXT UNIQUE,
      password TEXT
      );

    CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    title TEXT,
    description TEXT,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
    );
    `);
    // console.log('Tables created');
  };


// JWT Middleware

function authenticateToken(req, res, next) {
    console.log("coming to authenticateToken")
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    console.log("Token received:", token);  // Debug log

    if (!token) {
        console.log("Token missing");
        return res.status(401).json({ error: "Token missing. Unauthorized access" });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error("Token verification failed:", err);
            return res.status(403).json({ error: "Invalid token. Forbidden access" });
        }
        console.log("Token verified, user:", user);  // Debug log
        req.user = user;
        next();
    });
}


// Helper functions
async function hashPassword(password) {
    return await bcrypt.hash(password, 10);
  }
  async function comparePasswords(password, hash) {
    return await bcrypt.compare(password, hash);
  }
  function generateToken(user) {
    return jwt.sign(user, JWT_SECRET, { expiresIn: '1h' });
  }




// Signup
app.post('/api/auth/signup', async (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = await hashPassword(password);
    const id = uuidv4();

    try {
        // Check if the user already exists
        const existingUser = await db.get(`SELECT * FROM users WHERE email = ?`, [email]);
        if (existingUser) {
            return res.status(400).json({ error: "User already exists." });
        }

        // Insert new user if not exists
        await db.run(
            `INSERT INTO users (id, name, email, password) VALUES (?, ?, ?, ?)`,
            [id, name, email, hashedPassword]
        );
        res.json({ message: "User registered successfully." });
    } catch (err) {
        console.error("Signup error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});

 

// Login
app.post('/api/auth/login', async (req, res) => {
    console.log("coming to login");
    const { email, password } = req.body;

    try {
        // Fetch the user with the given email
        const user = await db.get(`SELECT * FROM users WHERE email = ?`, [email]);
        
        // Check if the user exists and the password matches
        if (!user || !(await comparePasswords(password, user.password))) {
            return res.status(403).json({ error: "Invalid credentials" });
        }

        // Generate a JWT token for the user
        const token = generateToken({ id: user.id, email: user.email });
        res.json({ token });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: "Internal Server Error" });
    }
});



// Task Management Routes

// Create Task
app.post('/api/tasks', authenticateToken, async (req, res) => {
    console.log("coming to create task");
    const { title, description } = req.body;
    const id = uuidv4();
    const userId = req.user.id;

    if (!title || !description) {
        return res.status(400).json({ error: "Title and description are required" });
    }

    try {
        await db.run(
            `INSERT INTO tasks (id, user_id, title, description, status) VALUES (?, ?, ?, ?, 'pending')`,
            [id, userId, title, description]
        );
        res.json({ message: "Task created successfully." });
    } catch (err) {
        console.error("Error creating task:", err);
        res.status(500).json({ error: "Failed to create task" });
    }
});

// Read Tasks
app.get('/api/tasks', authenticateToken, async (req, res) => {
    console.log('coming to Read Task')
    const userId = req.user.id;
    try {
        const tasks = await db.all(`SELECT * FROM tasks WHERE user_id = ?`, [userId]);
        res.json(tasks);
    } catch (err) {
        console.error("Error retrieving tasks:", err);
        res.status(500).json({ error: "Failed to retrieve tasks" });
    }
});

// Update Task
app.put('/api/tasks/:taskId', authenticateToken, async (req, res) => {
    console.log("coming to update task")
    const { taskId } = req.params;
    const { title, description, status } = req.body;

    if (!title || !description || !status) {
        return res.status(400).json({ error: "Title, description, and status are required" });
    }

    try {
        const result = await db.run(
            `UPDATE tasks SET title = ?, description = ?, status = ? WHERE id = ? AND user_id = ?`,
            [title, description, status, taskId, req.user.id]
        );

        if (result.changes === 0) {
            return res.status(404).json({ error: "Task not found or you are not authorized to update this task" });
        }

        res.json({ message: "Task updated successfully." });
    } catch (err) {
        console.error("Error updating task:", err);
        res.status(500).json({ error: "Failed to update task" });
    }
});

// Delete Task
app.delete('/api/tasks/:taskId', authenticateToken, async (req, res) => {
    const { taskId } = req.params;

    try {
        const result = await db.run(
            `DELETE FROM tasks WHERE id = ? AND user_id = ?`,
            [taskId, req.user.id]
        );

        if (result.changes === 0) {
            return res.status(404).json({ error: "Task not found or you are not authorized to delete this task" });
        }

        res.json({ message: "Task deleted successfully." });
    } catch (err) {
        console.error("Error deleting task:", err);
        res.status(500).json({ error: "Failed to delete task" });
    }
});


  

// Profile Management Routes

// View Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    console.log('coming to view profile')
    const userId = req.user.id;
    console.log("Fetching profile for user ID:", userId);  // Debug log

    await db.get(`SELECT id, name, email FROM users WHERE id = ?`, [userId], (err, user) => {
        if (err) {
            console.error("Error retrieving profile:", err);  // Debug log
            return res.status(400).json({ error: "Failed to retrieve profile" });
        }
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }
        res.json(user);
    });
});


app.put('/api/profile', authenticateToken, async (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = password ? await hashPassword(password) : null;

    console.log("Updating profile for user ID:", req.user.id);  // Debug log
    console.log("New data:", { name, email, password: hashedPassword ? "hashed" : "unchanged" });  // Debug log

    db.run(
        `UPDATE users SET name = ?, email = ?, password = COALESCE(?, password) WHERE id = ?`,
        [name, email, hashedPassword, req.user.id],
        (err) => {
            if (err) {
                console.error("Error updating profile:", err);  // Debug log
                return res.status(400).json({ error: "Failed to update profile" });
            }
            res.json({ message: "Profile updated successfully." });
        }
    );
});




