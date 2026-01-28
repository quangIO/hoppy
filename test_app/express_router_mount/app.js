const express = require("express");
const app = express();
const { apiRouterV1 } = require("./routers");

app.use("/api/v1", apiRouterV1.default);

module.exports = app;
