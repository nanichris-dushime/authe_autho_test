const express = require("express");
const authenticateToken = require("./authMiddleware");

const router = express.Router();

router.get("/dashboard", authenticateToken, (req, res) => {
  res.json({
    message: "Welcome to the dashboard",
    user: req.user
  });
});

module.exports = router;
