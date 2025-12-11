
const users = require("../model/userModel");
const jwt = require('jsonwebtoken')
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");

// REGISTER CONTROLLER
exports.registerController = async (req, res) => {
  try {
    let { username, email, password, college, role } = req.body;

    // 1️⃣ Validate input
    if (!username || !email || !password || !college) {
      return res.status(400).json({ message: "Please fill all required fields" });
    }

    // 2️⃣ Normalize email (trim + lowercase)
    email = email.trim().toLowerCase();

    // 3️⃣ Check if user already exists (case-insensitive)
    const existingUser = await users.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "Account already exists" });
    }

    // 4️⃣ Hash password (bcrypt)
    const hashedPassword = await bcrypt.hash(password, 10);

    // 5️⃣ Create new user
    const newUser = new users({
      username,
      email,
      password: hashedPassword,
      college,
      role: role || "user", // fallback to default user
      github: "",
      linkedin: "",
      profile: ""
    });

    // 6️⃣ Save to database
    await newUser.save();

    // 7️⃣ Exclude password before sending response
    const { password: _, ...userData } = newUser.toObject();

    res.status(201).json({
      message: "Registration successful 🎉",
      user: userData
    });

  } catch (error) {
    console.error("Registration failed:", error);

    // handle duplicate key error from MongoDB
    if (error.code === 11000) {
      return res.status(409).json({ message: "Email already registered" });
    }

    res.status(500).json({
      message: "Registration failed",
      error: error.message
    });
  }
};

//login
exports.loginController = async (req, res) => {
  const { email, password } = req.body;

  try {
    const existingUser = await users.findOne({ email });
    if (!existingUser) {
      return res.status(406).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign(
      { userId: existingUser._id, role: existingUser.role },
      process.env.JWT_SECRET || "supersecretKey",
      { expiresIn: "7d" }
    );

    // ✅ Return in expected structure
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


/// Temporary in-memory store for OTPs (replace with Redis in prod)
const otpStore = {}; // { "<email>": { otp, expiresAt, verified } }

// Transporter singleton
let _transporter = null;

function createTransporter() {
  if (_transporter) return _transporter;

  const transportOptions = {
    host: process.env.SMTP_HOST || "smtp.gmail.com",
    port: Number(process.env.SMTP_PORT || 587),
    secure: (process.env.SMTP_SECURE === "true"), // set "true" for 465
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS, // app password or SMTP password
    },
    pool: true, // keep connections open and reuse
    connectionTimeout: Number(process.env.SMTP_CONN_TIMEOUT) || 30000,
    greetingTimeout: Number(process.env.SMTP_GREETING_TIMEOUT) || 30000,
    socketTimeout: Number(process.env.SMTP_SOCKET_TIMEOUT) || 60000,
    logger: (process.env.DEBUG_MAIL === "true"),
    debug: (process.env.DEBUG_MAIL === "true"),
  };

  // only add TLS override if explicitly requested
  if (process.env.SMTP_REJECT_UNAUTHORIZED === "false") {
    transportOptions.tls = { rejectUnauthorized: false };
  }

  _transporter = nodemailer.createTransport(transportOptions);

  // verify transporter on creation (logs appear only when DEBUG_MAIL=true)
  _transporter.verify().then(
    () => {
      if (process.env.DEBUG_MAIL === "true") {
        console.log("MAILER: transporter verified and ready.");
      }
    },
    (err) => {
      console.error("MAILER: transporter verification failed:", err && err.message ? err.message : err);
    }
  );

  return _transporter;
}

// Utility: check if debug mode is on
function isDebug() {
  return process.env.DEBUG_MAIL === "true";
}

/**
 * SEND OTP
 */
exports.sendOtpController = async (req, res) => {
  try {
    console.log("SEND-OTP request body:", { email: !!req.body.email });

    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email is required" });

    const user = await users.findOne({ email });
    if (!user) return res.status(404).json({ message: "No account found" });

    // generate 6-digit OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000, verified: false };

    const transporter = createTransporter();

    const mailOptions = {
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: email,
      subject: process.env.OTP_SUBJECT || "Your OTP Code",
      text: `Your OTP is: ${otp}. It expires in 5 minutes.`,
      // html: `<p>Your OTP is <strong>${otp}</strong>. It expires in 5 minutes.</p>`
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      console.log("SEND-OTP success:", { messageId: info && info.messageId ? info.messageId : null });

      // respond lightly; include info only if debugging
      const response = { message: "OTP sent" };
      if (isDebug()) response.info = info;
      return res.status(200).json(response);
    } catch (smtpErr) {
      console.error("SEND-OTP SMTP ERROR:", smtpErr && smtpErr.message ? smtpErr.message : smtpErr);

      // Provide safe debug info only when DEBUG_MAIL=true
      if (isDebug()) {
        return res.status(502).json({
          message: "SMTP send failed (DEBUG)",
          errorMessage: smtpErr && smtpErr.message ? smtpErr.message : String(smtpErr),
          code: smtpErr && smtpErr.code ? smtpErr.code : null,
          response: smtpErr && smtpErr.response ? smtpErr.response : null,
          stack: smtpErr && smtpErr.stack ? smtpErr.stack : null,
        });
      }

      // production-safe response
      return res.status(502).json({ message: "Failed to send OTP" });
    }
  } catch (err) {
    console.error("SEND-OTP outer error:", err && err.stack ? err.stack : err);
    return res.status(500).json({ message: "Server error", error: isDebug() ? String(err) : undefined });
  }
};

/**
 * VERIFY OTP
 */
exports.verifyOtpController = async (req, res) => {
  try {
    console.log("VERIFY-OTP request body:", { email: !!req.body.email, otpProvided: !!req.body.otp });

    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ message: "Email and OTP are required" });

    const stored = otpStore[email];
    if (!stored) return res.status(400).json({ message: "OTP expired or not found" });
    if (Date.now() > stored.expiresAt) {
      delete otpStore[email];
      return res.status(400).json({ message: "OTP expired" });
    }
    if (stored.otp !== otp) return res.status(400).json({ message: "Invalid OTP" });

    // mark verified
    otpStore[email].verified = true;
    // optionally remove otp value to prevent reuse but keep verified flag
    // delete otpStore[email].otp;

    if (isDebug()) console.log("OTP verified for:", email, "storeSnapshot:", otpStore[email]);

    return res.status(200).json({ message: "OTP verified successfully" });
  } catch (error) {
    console.error("VERIFY-OTP Error:", error && error.stack ? error.stack : error);
    return res.status(500).json({ message: "Error verifying OTP", error: isDebug() ? error.message : undefined });
  }
};

/**
 * RESET PASSWORD
 */
exports.resetPasswordController = async (req, res) => {
  try {
    console.log("RESET-PASSWORD request body:", { email: !!req.body.email, newPasswordProvided: !!req.body.new_password });

    const { email, new_password } = req.body;
    if (!email || !new_password) return res.status(400).json({ message: "Email and new password are required" });

    const otpData = otpStore[email];
    if (!otpData || !otpData.verified) return res.status(400).json({ message: "OTP verification required" });

    // basic password policy (example — adjust as needed)
    if (String(new_password).length < 6) return res.status(400).json({ message: "Password must be at least 6 characters" });

    const hashedPassword = await bcrypt.hash(new_password, 10);
    const result = await users.updateOne({ email }, { $set: { password: hashedPassword } });

    if (isDebug()) console.log("Password update result:", result);

    // remove OTP record
    delete otpStore[email];

    return res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    console.error("RESET-PASSWORD Error:", error && error.stack ? error.stack : error);
    return res.status(500).json({ message: "Error resetting password", error: isDebug() ? error.message : undefined });
  }
};

// update profile
exports.editProfileController = async (req, res) => {
  console.log("---- Incoming Request Data ----");
  console.log("Body:", req.body);     // all text fields
  console.log("File:", req.file);     // uploaded file (if any)
  console.log("User From JWT:", req.user);  
  console.log("--------------------------------");

  const userId = req.user?.id;

  if (!userId) {
    console.log("❌ Unauthorized: userId missing from JWT");
    return res.status(401).json({ message: "Unauthorized - user id not found" });
  }

  // No data sent  
  if ((!req.body || Object.keys(req.body).length === 0) && !req.file) {
    console.log("❌ No data received from frontend");
    return res.status(400).json({ message: "No data received. Please send some fields." });
  }

  const { username, email, phone, college, github, linkedin, profile } = req.body;

  // Determine image: file → filename, otherwise profile field
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


//profile info

exports.profileInfoController = async (req, res) => {
  try {
    // JWT middleware sets: req.user = { id, role }
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({ message: "Unauthorized - user ID missing" });
    }

    // Fetch user from DB (exclude password & __v)
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

