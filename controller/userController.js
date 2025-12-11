
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


// Temporary in-memory store for OTPs (replace with Redis in prod)
const otpStore = {};

// Helper to create transporter based on env
function createTransporter() {
  const host = process.env.SMTP_HOST || "smtp.gmail.com";
  const port = process.env.SMTP_PORT ? Number(process.env.SMTP_PORT) : 587;
  const secure = process.env.SMTP_SECURE === "true" ? true : (port === 465);

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
      // for OAuth2 you'd include type, clientId, clientSecret, refreshToken
    },
    logger: true,
    debug: true,
    // optional pool and connectionTimeout
    pool: true,
    connectionTimeout: 10_000, // 10s
    greetingTimeout: 10_000,
  });
}

// SEND OTP
exports.sendOtpController = async (req, res) => {
  try {
    console.log("SEND-OTP: incoming request", { path: req.path, bodyPresent: !!req.body });

    const { email } = req.body;
    if (!email) return res.status(400).json({ message: "Email is required" });

    const user = await users.findOne({ email });
    if (!user) {
      console.warn("SEND-OTP: no user for email", email);
      return res.status(404).json({ message: "No account found with this email" });
    }

    // Generate OTP (6 digits)
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpStore[email] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 };

    const transporter = createTransporter();

    // verify transporter connectivity/auth before sending
    try {
      const verifyInfo = await transporter.verify();
      console.log("SMTP verify success:", verifyInfo);
    } catch (verifyErr) {
      console.error("SMTP verify failed:", verifyErr && verifyErr.message ? verifyErr.message : verifyErr);
      // Return an explicit error so you know it failed in hosted environment
      return res.status(502).json({ message: "SMTP verify failed", error: String(verifyErr) });
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset OTP - Student Chapter",
      text: `Your OTP for password reset is: ${otp}\n\nThis OTP is valid for 5 minutes.`,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log(`OTP sent to ${email}; sendMail info:`, info);

    return res.status(200).json({ message: "OTP sent successfully", debug: { messageId: info.messageId } });
  } catch (error) {
    console.error("Send OTP FULL ERROR:", error);
    return res.status(500).json({
      message: "Failed to send OTP",
      error: error.message,
      code: error.code || null,
      response: error.response || null,
    });
  }
};

// VERIFY OTP (no change, but log more)
exports.verifyOtpController = async (req, res) => {
  try {
    console.log("VERIFY-OTP request body:", req.body);
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ message: "Email and OTP are required" });

    const storedOtp = otpStore[email];
    if (!storedOtp) return res.status(400).json({ message: "OTP expired or not found" });
    if (storedOtp.otp !== otp) return res.status(400).json({ message: "Invalid OTP" });
    if (Date.now() > storedOtp.expiresAt) { delete otpStore[email]; return res.status(400).json({ message: "OTP expired" }); }

    otpStore[email].verified = true;
    console.log("OTP Store after verify:", otpStore);
    return res.status(200).json({ message: "OTP verified successfully" });
  } catch (error) {
    console.error("Verify OTP Error:", error);
    return res.status(500).json({ message: "Error verifying OTP", error: error.message });
  }
};

// RESET PASSWORD (log and minor hardening)
exports.resetPasswordController = async (req, res) => {
  try {
    console.log("RESET-PASSWORD request body:", { email: req.body.email ? true : false });
    const { email, new_password } = req.body;
    if (!email || !new_password) return res.status(400).json({ message: "Email and new password are required" });

    const otpData = otpStore[email];
    if (!otpData || !otpData.verified) return res.status(400).json({ message: "OTP verification required" });

    const hashedPassword = await bcrypt.hash(new_password, 10);
    const result = await users.updateOne({ email }, { $set: { password: hashedPassword } });

    console.log("Password update result:", result);
    delete otpStore[email];
    return res.status(200).json({ message: "Password reset successful" });
  } catch (error) {
    console.error("Reset Password Error:", error);
    return res.status(500).json({ message: "Error resetting password", error: error.message });
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

