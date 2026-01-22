const mysql = require("mysql2");

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",          
  database: "registration"
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed");
    return;
  }
  console.log("Connected to MySQL");
});

module.exports = db;
