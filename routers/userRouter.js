const router = require("express").Router();
const userCtrl = require("../controllers/userCtrl");

// router.post("/register", (req, res) => {
//   res.json({ msg: "Test register, Test Router" });
// });

// Registers
router.post("/register", userCtrl.register);
// Login
router.post("/login", userCtrl.login);
// Refresh Token
router.get("/refresh_token", userCtrl.refreshToken);

module.exports = router;
