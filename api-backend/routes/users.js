const router = require("express").Router();
const ctrl = require("../controllers/usersController");
router.get("/", ctrl.getUsers);
router.post("/login", ctrl.login);
module.exports = router;
