import express from "express";
import jwt from "jsonwebtoken";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
import bcrypt from "bcryptjs";

dotenv.config();

const app = express();

// --- config ---
const PORT = process.env.PORT || 8080;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "7d";
const CORS_ORIGINS = (process.env.CORS_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);

// Allow your site + your extension
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true); // allow curl/postman
    if (CORS_ORIGINS.length === 0 || CORS_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error("Not allowed by CORS"));
  },
  credentials: false
}));
app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(morgan("tiny"));

// --- Fake user store (replace with DB) ---
/**
 * In production, fetch the user by email from your DB,
 * compare `bcrypt.compare(plaintext, user.password_hash)`,
 * and read subscription_status from your DB.
 */
const users = [
  {
    email: "user@example.com",
    // password is "user_password"
    password_hash: bcrypt.hashSync("user_password", 10),
    subscription_status: "free" // or "subscribed"
  }
];

function findUserByEmail(email) {
  return users.find(u => u.email.toLowerCase() === String(email).toLowerCase());
}

// --- Auth helpers ---
function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");
  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // { email, subscription_status, iat, exp }
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

// --- API Routes (prefix /api) ---
const api = express.Router();

// 1) Login Endpoint: POST /api/auth/login
api.post("/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const user = findUserByEmail(email);
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = signToken({ email: user.email, subscription_status: user.subscription_status });
  return res.status(200).json({
    token,
    email: user.email,
    subscription_status: user.subscription_status
  });
});

// 2) Auth Verification Endpoint: GET /api/auth/verify
api.get("/auth/verify", authMiddleware, (req, res) => {
  // You could re-check DB here for up-to-date subscription status if needed
  return res.status(200).json({
    subscription_status: req.user.subscription_status === "subscribed" ? "subscribed" : "free"
  });
});

app.use("/api", api);

// health check (optional)
app.get("/healthz", (req, res) => res.status(200).send("ok"));

app.listen(PORT, () => {
  console.log(`API listening on :${PORT}`);
});
