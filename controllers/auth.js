const crypto = require("crypto");
const User = require("../models/user");
const bcrypt = require("bcrypt");
const nodeMailer = require("nodemailer");
const sendGridTransport = require("nodemailer-sendgrid-transport");
const { validationResult } = require("express-validator");

const transporter = nodeMailer.createTransport(
  sendGridTransport({
    auth: {
      api_key: process.env.SENDGRID_API,
    },
  })
);

exports.getLogin = (req, res, next) => {
  console.log(process.env.SENDGRID_API);
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render("auth/login", {
    path: "/login",
    pageTitle: "Login",
    csrfToken: req.csrfToken(),
    errorMessage: message,
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
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;

  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        req.flash("error", "Invalid email");
        return res.redirect("/login");
      }
      bcrypt
        .compare(password, user.password)
        .then((result) => {
          if (result) {
            req.session.user = user;
            req.session.isLoggedIn = true;
            return req.session.save(() => {
              res.redirect("/");
            });
          }
          req.flash("error", "Incorrect password");
          res.redirect("/login");
        })
        .catch((err) => console.log(err));
    })
    .catch((err) => console.log(err));
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const confirmPassword = req.body.confirmPassword;

  const errors = validationResult(req);
  console.log(errors.array());
  if (!errors.isEmpty()) {
    return res.status(422).render("auth/signup", {
      path: "/signup",
      pageTitle: "Signup",
      errorMessage: errors.array(),
    });
  }

  User.findOne({ email: email })
    .then((userDoc) => {
      if (userDoc) {
        req.flash("error", "This email is already used.");
        return res.redirect("/signup");
      }
      return bcrypt
        .hash(password, 12)
        .then((hashPassword) => {
          const user = new User({
            email: email,
            password: hashPassword,
            cart: { items: [] },
          });
          return user.save();
        })
        .then(() => {
          res.redirect("/");
          return transporter.sendMail({
            to: email,
            from: "myintaungm104@gmail.com",
            subject: "Signup Successfully!",
            html: "<h1>Signup Completed</h1>",
          });
        })
        .catch((err) => console.log(err));
    })
    .catch((err) => console.log(err));
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
    pageTitle: "Reset Password",
    path: "/reset",
    csrfToken: req.csrfToken(),
    errorMessage: message,
  });
};

exports.postReset = (req, res, next) => {
  const { email } = req.body;
  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        req.flash("error", "The is no user with such email.");
        return res.redirect("/reset");
      }
      crypto.randomBytes(32, (err, buffer) => {
        if (err) {
          return res.redirect("/reset");
        }
        const token = buffer.toString("hex");
        user.resetToken = token; //* can reset only with this token
        user.resetTokenExpiration = Date.now() + 3600000; //* adding token expiration date
        user
          .save()
          .then((result) => {
            res.redirect("/");
            return transporter.sendMail({
              to: email,
              from: "myintaungm104@gmail.com",
              subject: "Reset Password",
              html: `
              <p>Resetting Your Password</p>
              <p>click the <a href="http://localhost:3000/reset/${token}">link</a> to reset your password</p>
            `,
            });
          })
          .catch((err) => console.log(err));
      });
    })

    .catch((err) => console.log(err));
};

exports.getNewPassword = (req, res, next) => {
  let message = req.flash("error");
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }

  const token = req.params.token;
  User.findOne({
    resetToken: token,
    resetTokenExpiration: { $gt: new Date() },
  })
    .then((user) => {
      if (!user) {
        req.flash("error", "Invalid reset link");
        return res.redirect("/reset");
      }
      res.render("auth/new-password", {
        pageTitle: "New Password",
        path: "/new-password",
        csrfToken: req.csrfToken(),
        errorMessage: message,
        userId: user._id.toString(),
      });
    })
    .catch((err) => console.log(err));
};

exports.postNewPassword = (req, res, next) => {
  const userId = req.body.userId;
  const newPassword = req.body.password;
  User.findOne({ _id: userId })
    .then((user) => {
      if (!user) {
        req.flash("error", "Something went wrong! Try again later");
        res.redirect("/reset");
      }
      bcrypt
        .hash(newPassword, 12)
        .then((hashPassword) => {
          user.password = hashPassword;
          user.resetToken = null;
          user.resetTokenExpiration = null;
          return user.save();
        })
        .then((result) => {
          req.flash("error", "Password reset successfully");
          return res.redirect("/login");
        })
        .catch((err) => console.log(err));
    })
    .catch((err) => console.log(err));
};
