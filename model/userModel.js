const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    lowercase: true,   // keep lowercase
    trim: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
   phone: {
    type: String,
    default: ""
  },
  college: {
    type: String,
    required: true
  },
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user"
  },
  github: { type: String, default: "" },
  linkedin: { type: String, default: "" },
  profile: { type: String, default: "" },
  avatarDataUrl: { type: String, default: "" },
  skill: { type: String, default: "" },
  track: { type: String, default: "" },
}, { timestamps: true });

// Case-insensitive unique index
userSchema.index(
  { email: 1 },
  { unique: true, collation: { locale: "en", strength: 2 } }
);

module.exports = mongoose.model("users", userSchema);
