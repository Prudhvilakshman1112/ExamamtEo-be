import dotenv from "dotenv";
import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import cors from "cors";
import multer from "multer";
import fs from "fs";

dotenv.config(); // Load environment variables

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

app.use(express.json());
app.use(cors());
app.use("/uploads", express.static("uploads"));

// Database connection
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});

(async () => {
  try {
    await db.connect();
    console.log("Connected to PostgreSQL");
  } catch (err) {
    console.error("Database connection error:", err);
    process.exit(1);
  }
})();

// Middleware to log requests
app.use((req, res, next) => {
  console.log(`Received ${req.method} request at ${req.url}`);
  next();
});

// File upload setup (if needed for future use)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage });

// Signup route
app.post("/signup", async (req, res) => {
  const { name, email, password, role } = req.body;
  if (!name || !email || !password || !role) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const existingUser = await db.query(
      "SELECT * FROM users_auth WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await db.query(
      "INSERT INTO users_auth (name, email, password, role) VALUES ($1, $2, $3, $4)",
      [name, email, hashedPassword, role]
    );

    res.status(201).json({ message: "User registered successfully!" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Login route
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: "Email and password are required" });
  }

  try {
    const userResult = await db.query(
      "SELECT * FROM users_auth WHERE email = $1",
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: "User does not exist." });
    }

    const user = userResult.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: "Incorrect password." });
    }

    res.status(200).json({
      message: "Login successful!",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Upload Google Drive links route (SrDashboard)
app.post("/SrDashboard", async (req, res) => {
  try {
    const { username, password, subject, driveLink, OtherLink } = req.body;

    if (!username || !password || !subject || !driveLink || !OtherLink) {
      return res.status(400).json({ error: "Please fill all fields." });
    }

    // Hash password before storing (SECURITY FIX)
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const existingFile = await db.query(
      "SELECT file_paths, links FROM files WHERE username = $1 AND subject = $2",
      [username, subject]
    );

    if (existingFile.rows.length > 0) {
      await db.query(
        "UPDATE files SET file_paths = $1, links = $2 WHERE username = $3 AND subject = $4",
        [driveLink, OtherLink, username, subject]
      );
    } else {
      await db.query(
        "INSERT INTO files (username, password, file_paths, links, subject) VALUES ($1, $2, $3, $4, $5)",
        [username, hashedPassword, driveLink, OtherLink, subject]
      );
    }

    res.json({ message: "Drive link saved successfully", driveLink });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Junior Dashboard route
app.get("/Jrdashboard", async (req, res) => {
  const { seniorname } = req.query;
  if (!seniorname) {
    return res.status(400).json({ error: "Senior name is required" });
  }

  try {
    const files = await db.query(
      "SELECT * FROM files WHERE username = $1",
      [seniorname]
    );

    if (!files.rows.length) {
      return res.status(404).json({ error: "No files found for the specified senior" });
    }

    res.status(200).json({ files: files.rows });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Database Error" });
  }
});

// Explore route – returning Google Drive links directly
app.get("/explore", async (req, res) => {
  try {
    const files = await db.query("SELECT * FROM files");
    if (!files.rows.length) {
      return res.status(404).json({ error: "No files found" });
    }

    res.status(200).json({ files: files.rows });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Database Error" });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
