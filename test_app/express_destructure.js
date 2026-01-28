const express = require("express");

const app = express();
app.use(express.json());

app.post("/login", ({ body }, res) => {
  const userId = body.id;
  res.send(userId);
});

module.exports = app;
