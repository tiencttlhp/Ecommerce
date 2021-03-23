const Users = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const userCtrl = {
  //Check register
  register: async (req, res) => {
    try {
      const { name, email, password } = req.body;

      const user = await Users.findOne({ email });
      if (user)
        return res.status(400).json({ msg: "The email already exists" });

      if (password.length < 6)
        return res
          .status(400)
          .json({ msg: "Password is at least 6 characters" });

      //Password Encryption (Ma hoa)
      const passwordHash = await bcrypt.hash(password, 10);
      const newUser = new Users({
        name,
        email,
        password: passwordHash,
      });

      //Save MongoDB
      await newUser.save();

      //Then create jsonwebtoken to authentication
      const accesstoken = createAccesstoken({ id: newUser._id });
      const refreshtoken = createRefreshToken({ id: newUser._id });

      res.cookie("refreshtoken", refreshtoken, {
        httpOnly: true,
        path: "/user/refresh_token",
      });

      res.json({ accesstoken });
      // res.json({ msg:"Registers successfully" });
    } catch (error) {
      return res.status(500).json({ msg: error.message });
    }
  },
  // Check login
  login: async (req, res) => {
    try {
      const { email, password } = req.body;

      const user = await Users.findOne({ email });
      if (!user) return res.status(400).json({ msg: "User does not exits." });
      // Check password nhập vào với password data
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(400).json({ msg: "Incorrect password." });
      //If login success, create access token and refresh token
      const accesstoken = createAccesstoken({ id: user._id });
      const refreshtoken = createRefreshToken({ id: user._id });

      res.cookie("refreshtoken", refreshtoken, {
        httpOnly: true,
        path: "/user/refresh_token",
      });

      res.json({ accesstoken });
      // res.json({ msg: "Login Success!!!" });
    } catch (error) {
      return res.status(500).json({ msg: error.message });
    }
  },

  refreshToken: (req, res) => {
    try {
      const rf_token = req.cookies.refreshtoken;

      if (!rf_token)
        return res.status(400).json({ msg: "Please login of register" });

      jwt.verify(rf_token, process.env.REFRESH_TOKEN_SECRET, (error, user) => {
        if (error)
          return res.status(400).json({ msg: "Please login of register" });
        const accesstoken = createAccesstoken({ id: user.id });
        res.json({ user, accesstoken });
      });

      //   res.json({ rf_token });
    } catch (error) {
      return res.status(500).json({ msg: error.message });
    }
  },
};

const createAccesstoken = (user) => {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "1d" });
};

const createRefreshToken = (user) => {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "7d" });
};

module.exports = userCtrl;
