// controllers/authController.js
"use strict";

const users = require("../model/userModel");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const axios = require("axios");
const crypto = require("crypto");
const Redis = require("ioredis");

// -------------------- Config --------------------
// Uses env vars you already have. If RESET_TOKEN_SECRET or REDIS_URL are added later,
// the code will automatically start using them.
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const EMAIL_FROM = process.env.EMAIL_FROM || process.env.EMAIL_USER || "no-reply@example.com";
const REDIS_URL = process.env.REDIS_URL || null;

// If RESET_TOKEN_SECRET not provided, fall back to JWT_SECRET (not ideal for prod)
const RESET_TOKEN_SECRET = process.env.RESET_TOKEN_SECRET || process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

const JWT_SECRET = process.env.JWT_SECRET || "supersecretKey"; // your existing JWT secret
const RESET_TOKEN_EXPIRES_IN = process.env.RESET_TOKEN_EXPIRES_IN || "15m";
const OTP_LENGTH = Number(process.env.OTP_LENGTH || 6);
const OTP_TTL_SECONDS = Number(process.env.OTP_TTL_SECONDS || 5 * 60);
const OTP_RESEND_COOLDOWN = Number(process.env.OTP_RESEND_COOLDOWN || 30);
const OTP_MAX_ATTEMPTS = Number(process.env.OTP_MAX_ATTEMPTS || 5);
const DEBUG = process.env.DEBUG_MAIL === "true";
const PWRESET_TTL_SECONDS = Number(process.env.PWRESET_TTL_SECONDS || 15 * 60); // 15 minutes
// -------------------- Redis (optional) --------------------
let redis;
let inMemoryStore = {}; // fallback if no Redis (not recommended for production)

if (REDIS_URL) {
  redis = new Redis(REDIS_URL);
  redis.on("error", (e) => console.error("Redis error:", e && e.message ? e.message : e));
} else {
  if (DEBUG) console.warn("REDIS_URL not set — falling back to in-memory OTP store (not recommended for production)");
}

// -------------------- Helpers --------------------
function isDebug() {
  return DEBUG;
}

function generateOtp(len = OTP_LENGTH) {
  let otp = "";
  for (let i = 0; i < len; i++) otp += Math.floor(Math.random() * 10).toString();
  return otp;
}

function hmacHash(value, salt) {
  return crypto.createHmac("sha256", salt).update(String(value)).digest("hex");
}

async function redisSetOtp(email, payload) {
  const key = `otp:${email}`;
  if (redis) {
    await redis.set(key, JSON.stringify(payload), "EX", OTP_TTL_SECONDS);
  } else {
    inMemoryStore[key] = { ...payload, expiresAt: Date.now() + OTP_TTL_SECONDS * 1000 };
  }
}

async function redisGetOtp(email) {
  const key = `otp:${email}`;
  if (redis) {
    const v = await redis.get(key);
    return v ? JSON.parse(v) : null;
  } else {
    const entry = inMemoryStore[key];
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      delete inMemoryStore[key];
      return null;
    }
    return entry;
  }
}

async function redisDelOtp(email) {
  const key = `otp:${email}`;
  if (redis) {
    await redis.del(key);
  } else {
    delete inMemoryStore[key];
  }
}

async function incrCounter(key, ttlSeconds) {
  if (redis) {
    const n = await redis.incr(key);
    if (n === 1) await redis.expire(key, ttlSeconds);
    return n;
  } else {
    const now = Date.now();
    if (!inMemoryStore[key]) {
      inMemoryStore[key] = { count: 1, expiresAt: now + ttlSeconds * 1000 };
      return 1;
    }
    if (now > inMemoryStore[key].expiresAt) {
      inMemoryStore[key] = { count: 1, expiresAt: now + ttlSeconds * 1000 };
      return 1;
    }
    inMemoryStore[key].count++;
    return inMemoryStore[key].count;
  }
}

async function getCounter(key) {
  if (redis) {
    const v = await redis.get(key);
    return v ? Number(v) : 0;
  } else {
    const entry = inMemoryStore[key];
    if (!entry) return 0;
    if (Date.now() > entry.expiresAt) {
      delete inMemoryStore[key];
      return 0;
    }
    return entry.count || 0;
  }
}

async function sendEmailViaBrevo(toEmail, subject, htmlContent, textContent) {
  if (!BREVO_API_KEY) throw new Error("BREVO_API_KEY not configured");
  const payload = {
    sender: { email: EMAIL_FROM },
    to: [{ email: toEmail }],
    subject: subject,
    htmlContent: htmlContent || `<p>${textContent || ""}</p>`,
    textContent: textContent || undefined,
  };
  const resp = await axios.post("https://api.brevo.com/v3/smtp/email", payload, {
    headers: {
      "api-key": BREVO_API_KEY,
      "Content-Type": "application/json",
    },
    timeout: 15000,
  });
  return resp.data;
}

// -------------------- Controllers --------------------

// REGISTER CONTROLLER
exports.registerController = async (req, res) => {
  try {
    let { username, email, password, college, role } = req.body;

    if (!username || !email || !password || !college) {
      return res.status(400).json({ message: "Please fill all required fields" });
    }

    email = email.trim().toLowerCase();

    const existingUser = await users.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Account already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new users({
      username,
      email,
      password: hashedPassword,
      college,
      role: role || "user",
      github: "",
      linkedin: "",
      profile: ""
    });

    await newUser.save();
    const { password: _, ...userData } = newUser.toObject();

    res.status(201).json({
      message: "Registration successful 🎉",
      user: userData
    });

  } catch (error) {
    console.error("Registration failed:", error);
    if (error.code === 11000) {
      return res.status(409).json({ message: "Email already registered" });
    }
    res.status(500).json({
      message: "Registration failed",
      error: error.message
    });
  }
};

// LOGIN CONTROLLER
exports.loginController = async (req, res) => {
  const { email, password } = req.body;

  try {
    const existingUser = await users.findOne({ email });
    if (!existingUser) {
      return res.status(406).json({ message: "Invalid email or password" });
    }

    // verify password
    const match = await bcrypt.compare(password, existingUser.password);
    if (!match) return res.status(406).json({ message: "Invalid email or password" });

    const token = jwt.sign(
      { userId: existingUser._id, role: existingUser.role },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.status(200).json({
      existingUser: {
        username: existingUser.username,
        email: existingUser.email,
        phone: existingUser.phone || "",
        role: existingUser.role,
      },
      token,
      role: existingUser.role,
    });
  } catch (error) {
    res.status(500).json({ message: "Login failed", error });
  }
};

// -------------------- New OTP / Reset Flow --------------------


// --- server-side pwreset flag helpers ---
async function setResetFlag(email, ttlSeconds = PWRESET_TTL_SECONDS) {
  const key = `pwreset:${email}`;
  if (redis) {
    await redis.set(key, "1", "EX", ttlSeconds);
  } else {
    inMemoryStore[key] = { value: "1", expiresAt: Date.now() + ttlSeconds * 1000 };
  }
}

async function hasResetFlag(email) {
  const key = `pwreset:${email}`;
  if (redis) {
    const v = await redis.get(key);
    return !!v;
  } else {
    const entry = inMemoryStore[key];
    if (!entry) return false;
    if (Date.now() > entry.expiresAt) {
      delete inMemoryStore[key];
      return false;
    }
    return true;
  }
}

async function delResetFlag(email) {
  const key = `pwreset:${email}`;
  if (redis) {
    await redis.del(key);
  } else {
    delete inMemoryStore[key];
  }
}

/**
 * SEND OTP
 * POST { email }
 */
exports.sendOtpController = async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ message: "Email is required" });

    const user = await users.findOne({ email });
    if (!user) return res.status(404).json({ message: "No account found" });

    // cooldown prevention
    const cooldownKey = `otp_cooldown:${email}`;
    const cooldownCount = await getCounter(cooldownKey);
    if (cooldownCount > 0) {
      return res.status(429).json({ message: `Please wait ${OTP_RESEND_COOLDOWN} seconds before requesting another OTP` });
    }

    // generate otp and hash it before storing
    const otp = generateOtp(OTP_LENGTH);
    const salt = crypto.randomBytes(16).toString("hex");
    const hashed = hmacHash(otp, salt);

    const meta = {
      hash: hashed,
      salt,
      verified: false,
      createdAt: Date.now(),
      attempts: 0
    };

    await redisSetOtp(email, meta);
    await incrCounter(cooldownKey, OTP_RESEND_COOLDOWN);
    await incrCounter(`otp_sends:${email}`, OTP_TTL_SECONDS);

    // send via Brevo (API)
    const subject = process.env.OTP_SUBJECT || "Your OTP Code";
    const html = `<p>Your One-Time Password (OTP) is <strong>${otp}</strong>. It will expire in ${Math.round(OTP_TTL_SECONDS/60)} minutes.</p>`;
    const text = `Your OTP is: ${otp}. It expires in ${Math.round(OTP_TTL_SECONDS/60)} minutes.`;

    let info;
    try {
      info = await sendEmailViaBrevo(email, subject, html, text);
      if (isDebug()) console.log("SEND-OTP success (brevo):", info);
    } catch (sendErr) {
      await redisDelOtp(email);
      console.error("SEND-OTP Email API error:", sendErr && sendErr.response ? sendErr.response.data : sendErr && sendErr.message ? sendErr.message : sendErr);
      if (isDebug()) {
        return res.status(502).json({
          message: "Failed to send OTP (email provider error)",
          error: sendErr && sendErr.response ? sendErr.response.data : String(sendErr),
        });
      }
      return res.status(502).json({ message: "Failed to send OTP" });
    }

    const out = { message: "OTP sent" };
    if (isDebug()) out.debug = { otp, internal: meta, emailApi: info };
    return res.status(200).json(out);

  } catch (err) {
    console.error("SEND-OTP outer error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ message: "Server error", error: isDebug() ? String(err) : undefined });
  }
};

/**
 * VERIFY OTP
 * POST { email, otp }
 * returns: { message, resetToken }
 */
exports.verifyOtpController = async (req, res) => {
  try {
    const { email, otp } = req.body || {};
    if (!email || !otp) return res.status(400).json({ message: "Email and OTP are required" });

    const stored = await redisGetOtp(email);
    if (!stored) return res.status(400).json({ message: "OTP expired or not found" });

    if ((stored.attempts || 0) >= OTP_MAX_ATTEMPTS) {
      await redisDelOtp(email);
      return res.status(429).json({ message: "Too many attempts. Please request a new OTP." });
    }

    const computed = hmacHash(otp, stored.salt);
    if (computed !== stored.hash) {
      stored.attempts = (stored.attempts || 0) + 1;
      await redisSetOtp(email, stored);
      return res.status(400).json({ message: "Invalid OTP" });
    }

    // mark verified
    stored.verified = true;
    await redisSetOtp(email, stored);

    // set short-lived server-side reset permission (pwreset:<email>)
    await setResetFlag(email, PWRESET_TTL_SECONDS);

    // also issue reset token as before (backwards-compatible)
    const payload = { email, purpose: "password_reset" };
    const token = jwt.sign(payload, RESET_TOKEN_SECRET, { expiresIn: RESET_TOKEN_EXPIRES_IN });

    const out = { message: "OTP verified", resetToken: token };
    if (isDebug()) out.debug = { stored };
    return res.status(200).json(out);

  } catch (err) {
    console.error("VERIFY-OTP Error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ message: "Error verifying OTP", error: isDebug() ? String(err) : undefined });
  }
};


/**
 * RESET PASSWORD
 * POST { email, new_password, reset_token }
 */
exports.resetPasswordController = async (req, res) => {
  try {
    const { email, new_password, reset_token } = req.body || {};
    if (!email || !new_password) {
      return res.status(400).json({ message: "Email and new password are required" });
    }

    // If reset_token provided -> validate JWT as before
    let tokenValid = false;
    if (reset_token) {
      try {
        const payload = jwt.verify(reset_token, RESET_TOKEN_SECRET);
        if (payload.email === email && payload.purpose === "password_reset") {
          tokenValid = true;
        } else {
          return res.status(400).json({ message: "Reset token mismatch" });
        }
      } catch (jwtErr) {
        return res.status(400).json({ message: "Invalid or expired reset token" });
      }
    }

    // If no valid token, check server-side pwreset flag
    if (!tokenValid) {
      const allowed = await hasResetFlag(email);
      if (!allowed) {
        return res.status(400).json({ message: "Password reset not authorized. Verify OTP first or provide reset token." });
      }
    }

    // password policy
    if (String(new_password).length < 6) return res.status(400).json({ message: "Password must be at least 6 characters" });

    // update password
    const hashedPassword = await bcrypt.hash(new_password, 10);
    const result = await users.updateOne({ email }, { $set: { password: hashedPassword } });
    if (isDebug()) console.log("Password update result:", result);

    // cleanup: remove OTP and reset flag so they cannot be reused
    await redisDelOtp(email);
    await delResetFlag(email);

    return res.status(200).json({ message: "Password reset successful" });
  } catch (err) {
    console.error("RESET-PASSWORD Error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ message: "Error resetting password", error: isDebug() ? String(err) : undefined });
  }
};

// -------------------- Other existing controllers (kept) --------------------

// update profile
exports.editProfileController = async (req, res) => {
  console.log("---- Incoming Request Data ----");
  console.log("Body:", req.body);
  console.log("File:", req.file);
  console.log("User From JWT:", req.user);
  console.log("--------------------------------");

  const userId = req.user?.id;

  if (!userId) {
    console.log("❌ Unauthorized: userId missing from JWT");
    return res.status(401).json({ message: "Unauthorized - user id not found" });
  }

  if ((!req.body || Object.keys(req.body).length === 0) && !req.file) {
    console.log("❌ No data received from frontend");
    return res.status(400).json({ message: "No data received. Please send some fields." });
  }

  const { username, email, phone, college, github, linkedin, profile } = req.body;
  const profileImage = req.file ? req.file.filename : profile;

  console.log("📌 Updating user with ID:", userId);
  console.log("📌 New profile image:", profileImage);

  try {
    const updatedUser = await users.findByIdAndUpdate(
      userId,
      {
        username,
        email,
        phone,
        college,
        github,
        linkedin,
        profile: profileImage,
      },
      { new: true }
    );

    if (!updatedUser) {
      console.log("❌ Update failed — user not found in DB");
      return res.status(404).json({ message: "User not found" });
    }

    console.log("✅ Profile updated successfully!");
    console.log("🔄 Updated User Data:", updatedUser);

    return res.status(200).json({
      message: "Profile updated successfully",
      user: updatedUser,
    });

  } catch (error) {
    console.error("❌ Update Error:", error);
    return res.status(500).json({ message: "Failed to update profile", error });
  }
};

// profile info
exports.profileInfoController = async (req, res) => {
  try {
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ message: "Unauthorized - user ID missing" });
    }

    const user = await users.findById(userId).select("-password -__v");

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    return res.status(200).json({ user });
  } catch (error) {
    console.error("profileInfoController error:", error);
    return res.status(500).json({ message: "Failed to fetch profile info" });
  }
};
