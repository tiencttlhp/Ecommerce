const router = require("express").Router();
const userCtrl = require("../controllers/userCtrl");

// router.post("/register", (req, res) => {
//   res.json({ msg: "Test register, Test Router" });
// });

router.post("/register", userCtrl.register);
router.get("/refresh_token", userCtrl.refreshToken);

module.exports = router;
