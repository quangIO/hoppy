const express = require("express");
const router = express.Router();
const userRouter = require("./user");

router.get("/hello", (req, res) => {
  res.send("ok");
});

router.use("/users", userRouter);

module.exports.default = router;
