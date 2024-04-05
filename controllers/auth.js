// This is built in node js pacakge use to generate random numbers and values and tokens etc.
const crypto = require("crypto");

const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");

const User = require("../models/user");
const { validationResult } = require("express-validator/check");

let transporter = nodemailer.createTransport({
  host: "smtp-relay.brevo.com",
  port: 587,
  secure: false, // true for 465, false for other ports
  auth: {
    user: "andhariyavalay4@gmail.com", // generated ethereal user
    pass: "ADv9QZzN2ban5mTM", // generated ethereal password
  },
});

exports.getLogin = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/login", {
    path: "/login",
    pageTitle: "Login",
    errorMessage: message,
    oldInput: { email: "", password: "" },
    validationErrors: [],
    reset: undefined,
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/signup", {
    path: "/signup",
    pageTitle: "Signup",
    errorMessage: message,
    oldInput: {
      email: "",
      password: "",
      confirmPassword: "",
    },
    validationErrors: [],
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // console.log(errors.array());
    return res.status(422).render("auth/login", {
      path: "/login",
      pageTitle: "Login",
      errorMessage: errors.array()[0].msg,
      oldInput: { email: email, password: password },
      validationErrors: errors.array(),
      reset: undefined,
    });
  }
  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        return res.status(422).render("auth/login", {
          path: "/login",
          pageTitle: "Login",
          errorMessage: "Email does not exist!",
          oldInput: { email: email, password: password },
          validationErrors: [{ param: "email" }],
          reset: undefined,
        });
      }

      bcrypt
        .compare(password, user.password)
        .then((doMatch) => {
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save((err) => {
              console.log(err);
              res.redirect("/");
              transporter.sendMail({
                from: '"ShopFromNodeJs" learning@brevo.com', // sender address
                to: email, // list of receivers
                subject: "Login Successfully ✔", // Subject line
                text: `Hello  ${
                  email.split("@")[0]
                }, You have Loggedin successfully in ShopByNodeJs`, // plain text body
              });
            });
          }

          return res.status(422).render("auth/login", {
            path: "/login",
            pageTitle: "Login",
            errorMessage: "Invalid Password.",
            oldInputs: { email: email, password: password },
            validationErrors: [{ param: "password" }],
            reset: undefined,
          });
        })
        .catch((err) => {
          console.log(err);
          res.redirect("/login");
        });
    })
    .catch((err) => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // console.log(errors.array());
    return res.status(422).render("auth/signup", {
      path: "/signup",
      pageTitle: "Signup",
      //you can direct access the message like this!
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
        confirmPassword: req.body.confirmPassword,
      },
      validationErrors: errors.array(),
    });
  }
  return bcrypt
    .hash(password, 12)
    .then((hashedPassword) => {
      const user = new User({
        email: email,
        password: hashedPassword,
        cart: { items: [] },
      });
      return user.save();
    })
    .then((result) => {
      res.redirect("/login");
      return transporter.sendMail({
        from: '"ShopFromNodeJs" learning@brevo.com', // sender address
        to: email, // list of receivers
        subject: "Register to ShopByNodeJs ✔", // Subject line
        text: `Hello  ${
          email.split("@")[0]
        }, Your Registration in ShopByNodeJs is completed successfully`, // plain text body
      });
    })
    .catch((err) => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.postLogout = (req, res, next) => {
  req.session.destroy((err) => {
    console.log(err);
    res.redirect("/");
  });
};

exports.getReset = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/reset", {
    path: "/reset",
    pageTitle: "Reset Password",
    errorMessage: message,
  });
};

exports.postReset = (req, res, next) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      return res.redirect("/reset");
    }
    const token = buffer.toString("hex");
    User.findOne({ email: req.body.email })
      .then((user) => {
        if (!user) {
          req.flash("error", "No Account with that email found!");
          return res.redirect("/reset");
        }
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000;
        return user.save();
      })
      .then(() => {
        res.render("auth/login", {
          path: "/login",
          pageTitle: "Login",
          errorMessage: undefined,
          oldInput: { email: "", password: "" },
          validationErrors: [],
          reset: true,
        });
        transporter.sendMail({
          from: '"ShopFromNodeJs" learning@brevo.com', // sender address
          to: req.body.email, // list of receivers
          subject: "Request to change password of ShopByNodeJs ✔", // Subject line
          html: `<h1>You requested to reset your password</h1>
          <p>Click this <a href="http://localhost:3000/reset/${token}">Reset Password</a> to set a new password.</p>
          `,
        });
      })
      .catch((err) => {
        console.log(err);
        const error = new Error(err);
        error.httpStatusCode = 500;
        return next(error);
      });
  });
};

exports.getNewPassword = (req, res, next) => {
  let token = req.params.token;
  User.findOne({
    resetToken: token,
    resetTokenExpiration: { $gt: Date.now() },
  })
    .then((user) => {
      let message = req.flash("error");
      if (message.length > 0) {
        message = message[0];
      } else {
        message = null;
      }
      res.render("auth/new-password", {
        path: "/new-password",
        pageTitle: "New Password",
        errorMessage: message,
        userId: user._id.toString(),
        passwordToken: token,
      });
    })
    .catch((err) => {
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};

exports.postNewPassword = (req, res, next) => {
  const userId = req.body.userId;
  const passToken = req.body.passwordToken;
  const newPassword = req.body.password;

  if (newPassword < 5) {
    res.render("auth/reset", {
      path: "/reset",
      pageTitle: "Reset Password",
      errorMessage: "Invalid password, please re-enter email!",
    });
  }

  let resetUser;
  User.findOne({
    _id: userId,
    resetToken: passToken,
    resetTokenExpiration: { $gt: Date.now() },
  })
    .then((user) => {
      console.log(user);
      resetUser = user;
      return bcrypt.hash(newPassword, 12);
    })
    .then((hashedPassword) => {
      resetUser.password = hashedPassword;
      resetUser.resetToken = undefined;
      resetUser.resetTokenExpiration = undefined;
      return resetUser.save();
    })
    .then((result) => {
      res.redirect("/login");
    })
    .catch((err) => {
      console.log(err);
      const error = new Error(err);
      error.httpStatusCode = 500;
      return next(error);
    });
};
