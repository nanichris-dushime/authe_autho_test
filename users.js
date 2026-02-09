const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./dbConnect");


const router = express.Router();

router.post("/register", async (req, res) => {
  const { username, password, role, department } = req.body;

  
  if (!username || !password || !role || !department) {
    return res.status(400).json({
      message: "All fields are required"
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const query =
      "INSERT INTO users (username, password, role, department) VALUES (?, ?, ?, ?)";

    db.execute(query, [username, hashedPassword, role, department], (err) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(409).json({ message: "Username already exists" });
        }
        console.error(err);
        return res.status(500).json({ message: "Database error" });
      }

      return res.status(201).json({
        message: "User registered successfully"
      });
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ message: "Server error" });
  }
});
 






router.post("/login", (req, res) => {
  const { username, password } = req.body;

  // 1️⃣ Find user by username
  const query = "SELECT * FROM users WHERE username = ?";

  db.execute(query, [username], async (err, results) => {
    if (err) {
      return res.status(500).json({ message: "Database error" });
    }

    // 2️⃣ Check if user exists
    if (results.length === 0) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    const user = results[0];

    // 3️⃣ Compare password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    // 4️⃣ Create JWT
    const token = jwt.sign(
      {
        id: user.id,
        role: user.role,
        department: user.department
      },
      "my_super_secret_key",
      { expiresIn: "1h" }
    );

    // 5️⃣ Send token
    return res.json({
      message: "Login successful",
      token
    });
  });
});



module.exports = router;
