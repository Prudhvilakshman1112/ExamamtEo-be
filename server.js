import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import cors from "cors";
import multer from "multer";
import fs from "fs";

const app = express();
app.use(express.json());
const port = 3000;
const saltRounds = 10;

// Database connection
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "Authentication",
  password: "prudhvi",
  port: 5432,
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

app.use(express.json());
app.use("/uploads", express.static("uploads"));
app.use(cors());

// Middleware to log requests
app.use((req, res, next) => {
  console.log(`Received ${req.method} request at ${req.url}`);
  next();
});

// Set up file upload using multer (if needed for other routes)
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + "-" + file.originalname);
  },
});
const upload = multer({ storage: storage });

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

// Upload files route – storing Google Drive links directly
app.post("/SrDashboard", async (req, res) => {
  try {
    const { username, password, subject, driveLink, OtherLink } = req.body;

    console.log("Request body received:", req.body);

    if (!username || !password || !subject || !driveLink || !OtherLink) {
      return res.status(400).json({ error: "Please fill all fields." });
    }

    const existingFile = await db.query(
      "SELECT file_paths, links FROM files WHERE username = $1 AND password = $2 AND subject = $3",
      [username, password, subject]
    );

    if (existingFile.rows.length > 0) {
      await db.query(
        "UPDATE files SET file_paths = array_append(file_paths, $1), links = $2 WHERE username = $3 AND password = $4 AND subject = $5",
        [driveLink, OtherLink, username, password, subject]
      );
    } else {
      await db.query(
        "INSERT INTO files (username, password, file_paths, links, subject) VALUES ($1, $2, $3, $4, $5)",
        [username, password, [driveLink], OtherLink, subject]
      );
    }

    res.json({ message: "Drive link saved successfully", driveLink });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Junior dashboard route
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

    if (!files.rows || files.rows.length === 0) {
      return res.status(404).json({ error: "No files found for the specified senior" });
    }

    // Returning drive links as stored in file_paths
    return res.status(200).json({ files: files.rows });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Database Error" });
  }
});


// Explore route – returning Google Drive links directly
app.get("/explore", async (req, res) => {
  try {
    const files = await db.query("SELECT * FROM files");
    if (!files.rows || files.rows.length === 0) {
      return res.status(404).json({ error: "No files found" });
    }

    // No URL prefixing; drive links are returned as stored.
    res.status(200).json({ files: files.rows });
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({ error: "Database Error" });
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
