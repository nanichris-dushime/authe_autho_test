const express = require("express");
const app = express();

// JSON parsing
app.use(express.json());

// Routes
const userRoutes = require("./users");
// Optional: protected routes
// const protectedRoutes = require("./protected");

app.use("/api", userRoutes);
// app.use("/api", protectedRoutes);

const PORT = 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
