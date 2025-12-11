const jwt = require("jsonwebtoken");

const jwtMiddleware = (req, res, next) => {
  try {
    // Get token from headers
    const token = req.headers["authorization"]?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    // Verify token
    const jwtResponse = jwt.verify(token, "supersecretKey");
    console.log("Decoded JWT:", jwtResponse);

    // Store user info in request
    req.user = {
      id: jwtResponse.userId,
      role: jwtResponse.role,  // ✅ save role
    };

    next();
  } catch (error) {
    res.status(401).json({ message: "Authorization failed, please login" });
  }
};

module.exports = jwtMiddleware;


