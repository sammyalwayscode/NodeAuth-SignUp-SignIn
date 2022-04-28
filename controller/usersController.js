const userModel = require("../model/userModel");
const { validateUsers, validateSignIn } = require("../utils/Validate");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const signUp = async (req, res) => {
  try {
    //Validate User
    const { error } = validateUsers(req.body);
    if (error) {
      res.status(409).json({
        status: "Failed to Validate user",
        message: error.details[0].message,
      });
    } else {
      //Verify User to check if user exist before
      const oldUser = await userModel.findOne({ email: req.body.email });
      if (oldUser) {
        res.json(`User Already Exist`);
      } else {
        //Then if userd dose not exist before it creates a new User

        //But it first of all salt the password to make the password unique ans secured

        //Salt The Password
        const saltedPassword = await bcrypt.genSalt(10);
        //Hash the Password
        const hashedPasword = await bcrypt.hash(
          req.body.password,
          saltedPassword
        );

        //Create user Object
        const userData = {
          fullName: req.body.fullName,
          course: req.body.course,
          duration: req.body.duration,
          username: req.body.username,
          email: req.body.email,
          password: hashedPasword,
        };

        //Create User
        const user = await userModel.create(userData);
        if (!user) {
          res.status(400).json({
            status: 400,
            message: "Failed to Create User",
          });
        } else {
          res.status(201).json({
            status: 201,
            data: user,
          });
        }
      }
    }
    //Catch Other Errors
  } catch (error) {
    res.json({ message: error.message });
  }
};

//Get All Users
const getAllUsers = async (req, res) => {
  try {
    const users = await userModel.find();
    if (users.length < 1) {
      res.status(404).json({
        status: 404,
        message: "No User in DataBase",
      });
    } else {
      res.status(200).json({
        status: 200,
        totalUsers: users.length,
        data: users,
      });
    }
  } catch (error) {
    res.status(404).json({
      status: 404,
      message: error.message,
    });
  }
};

//Sign In Users
const signIn = async (req, res) => {
  try {
    //Validate Sign In
    const { error } = validateSignIn(req.body);
    if (error) {
      res.status(409).json({
        status: "Can't sign In User",
        message: error.details[0].message,
      });
    } else {
      //Check if the users email matches with the one in the database
      const user = await userModel.findOne({ email: req.body.email });
      if (!user) {
        res.json({
          message: "User not Recognised",
        });
      } else {
        //If the user email matches then check if the password matches with the email provided
        const passwordCheck = await bcrypt.compare(
          req.body.password,
          user.password
        );
        if (!passwordCheck) {
          //If password does not matches then trow this error
          res.json({ message: "Invalid Password" });
        } else {
          //Then if Password matches Hide the passwore and Ecrypt the users Info
          const { password, ...info } = user._doc;
          const token = jwt.sign(
            //Payload or Data
            {
              _id: user._id,
              fullName: user.fullName,
              course: user.course,
              duration: user.duration,
              username: user.username,
              email: user.email,
            },
            //Secrete
            "mytoken",
            //option

            //Set the time limit of when the token will expire which in this case is TWO Days

            //Then after this time if the user logsin back it generates a new token for the user

            { expiresIn: "2d" }
          );
          res.json({
            //Then if validation is sucessfull it logs in the USER
            message: `Welcome back ${user.fullName}`,
            data: { token },
          });
        }
      }
    }
  } catch (error) {
    res.status(500).json({
      status: 500,
      message: error.message,
    });
  }
};

module.exports = { signUp, getAllUsers, signIn };
