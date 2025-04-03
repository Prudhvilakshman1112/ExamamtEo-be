import dotenv from "dotenv";
import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import cors from "cors";
import multer from "multer";
import fs from "fs";

dotenv.config(); // Load environment variables

const app = express();
const port = process.env.PORT || 10000; // Ensure correct port binding
const saltRounds = 10;

app.use(express.json());
app.use(cors());
app.use("/uploads", express.static("uploads"));

// Database connection
const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false, // Required for Render PostgreSQL
  },
});

(async () => {
  try {
    await db.connect();
    console.log("✅ Connected to PostgreSQL on Render");
  } catch (err) {
    console.error("❌ Database connection error:", err);
    process.exit(1);
  }
})();

// Middleware to log requests
app.use((req, res, next) => {
  console.log(`📩 Received ${req.method} request at ${req.url}`);
  next();
});

// ✅ Add a root route to prevent "Cannot GET /"
app.get("/", (req, res) => {
  res.status(200).json({ message: "Backend is running 🚀" });
});

// ✅ Explore Route (Fixed)
app.get("/explore", async (req, res) => {
  try {
    const files = await db.query("SELECT * FROM files");
    if (!files.rows.length) {
      return res.status(404).json({ error: "No files found" });
    }
    res.status(200).json({ files: files.rows });
  } catch (error) {
    console.error("❌ Database error in /explore:", error);
    res.status(500).json({ error: "Database Error" });
  }
});

// ✅ Signup Route
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
    console.error("❌ Signup Error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// ✅ Login Route
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
    console.error("❌ Login error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// ✅ Start the Server
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
