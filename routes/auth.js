import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import pool from "../db.js";
import { requireAuth } from "../middleware/auth.js";

const router = express.Router();

function mapServerError(error, defaultMessage) {
  const code = error?.code;

  if (code === "ER_NO_SUCH_TABLE") {
    return "Database is missing required tables. Run schema.sql before signing up.";
  }
  if (code === "ER_BAD_DB_ERROR") {
    return "Configured database does not exist. Check DB_NAME in backend/.env.";
  }
  if (code === "ER_ACCESS_DENIED_ERROR" || code === "ER_DBACCESS_DENIED_ERROR") {
    return "Database credentials are invalid. Check DB_USER and DB_PASSWORD in backend/.env.";
  }
  if (code === "ECONNREFUSED" || code === "ENOTFOUND" || code === "ETIMEDOUT") {
    return "Cannot connect to database. Verify DB_HOST, DB_PORT, and database availability.";
  }

  return defaultMessage;
}

function buildCookieOptions() {
  return {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === "true",
    sameSite: "strict",
    maxAge: 24 * 60 * 60 * 1000
  };
}

router.post("/register", async (req, res) => {
  const { username, email, phone, password } = req.body;

  if (!username || !email || !phone || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const [existing] = await pool.execute(
      "SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1",
      [username, email]
    );

    if (existing.length > 0) {
      return res.status(409).json({ message: "Username or email already exists" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    await pool.execute(
      "INSERT INTO users (username, email, phone, password_hash, role) VALUES (?, ?, ?, ?, ?)",
      [username, email, phone, passwordHash, "USER"]
    );

    return res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    const message = mapServerError(error, "Registration failed");
    const payload = { message };
    if (process.env.NODE_ENV !== "production") {
      payload.error = error.message;
      payload.code = error.code || null;
    }
    return res.status(500).json(payload);
  }
});

router.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  try {
    const [rows] = await pool.execute(
      "SELECT id, username, password_hash, role FROM users WHERE username = ? LIMIT 1",
      [username]
    );

    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = rows[0];
    const passwordMatches = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatches) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { sub: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || "1d" }
    );

    res.cookie("token", token, buildCookieOptions());
    return res.status(200).json({
      message: "Login successful",
      user: { username: user.username, role: user.role }
    });
  } catch (error) {
    const message = mapServerError(error, "Login failed");
    const payload = { message };
    if (process.env.NODE_ENV !== "production") {
      payload.error = error.message;
      payload.code = error.code || null;
    }
    return res.status(500).json(payload);
  }
});

router.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.COOKIE_SECURE === "true",
    sameSite: "strict"
  });
  return res.status(200).json({ message: "Logged out successfully" });
});

router.get("/me", requireAuth, (req, res) => {
  return res.status(200).json({
    authenticated: true,
    user: {
      username: req.user.sub,
      role: req.user.role
    }
  });
});

export default router;
