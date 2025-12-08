const express = require("express");
const app = express();
const userRoutes = require("./routes/users");
const requestLogger = require("./middlewares/requestLogger");

app.use(express.json());
app.use(requestLogger);
app.use("/api/users", userRoutes);

app.get("/", (req, res) => res.json({ status: "ok" }));

app.listen(8080, () => console.log("API running"));
