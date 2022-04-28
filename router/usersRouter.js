const express = require("express");
const router = express.Router();
const {
  signUp,
  signIn,
  getAllUsers,
} = require("../controller/usersController");

router.route("/user/signup").post(signUp);
router.route("/users").get(getAllUsers);
router.route("/users/signin").post(signIn);

module.exports = router;
