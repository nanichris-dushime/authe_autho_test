const express = require("express");
const app = express();

app.use(express.json());

const userRoutes = require("./users");
const protectedRoutes = require("./protected");

app.use("/api", userRoutes);
app.use("/api", protectedRoutes);

const PORT = 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
