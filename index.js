const express = require("express");
const JWT_SECRET = "my_super_secret_key";
const app = express();

app.use(express.json());

const userRoutes = require("./users");
app.use("/api", userRoutes);

const PORT = 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
