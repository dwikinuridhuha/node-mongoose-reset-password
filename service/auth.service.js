const JWT = require("jsonwebtoken");
const User = require("../model/User.model");
const Token = require("../model/Token.model");
const sendEmail = require("../utils/email/sendEmail");
const crypto = require("crypto");
const bcrypt = require("bcrypt");

const signup = async (data) => {
    let user = await User.findOne({
        email: data.email
    });
    if (user) {
        throw new Error("Email already exist");
    }
    user = new User(data);
    const token = JWT.sign({
        id: user._id
    }, "JWTSecret");
    await user.save();
    return (data = {
        userId: user._id,
        email: user.email,
        name: user.name,
        token: token,
    });
};

const requestPasswordReset = async (email) => {

    const user = await User.findOne({
        email
    });

    if (!user) throw new Error("User does not exist");

    let token = await Token.findOne({
        userId: user._id
    });

    if (token) await token.deleteOne();

    let resetToken = crypto.randomBytes(32).toString("hex");

    const hash = await bcrypt.hash(resetToken, Number(10));

    await new Token({
        userId: user._id,
        token: hash,
        createdAt: Date.now(),
    }).save();

    const link = `localhost:8080/passwordReset?token=${resetToken}&id=${user._id}`;

    const ok = sendEmail(user.email, "Password Reset Request", {
        name: user.name,
        link: link,
    }, "./template/requestResetPassword.handlebars");

    return ok;
};

const resetPassword = async (userId, token, password) => {
    let passwordResetToken = await Token.findOne({
        userId
    });
    if (!passwordResetToken) {
        throw new Error("Invalid or expired password reset token");
    }
    const isValid = await bcrypt.compare(token, passwordResetToken.token);
    if (!isValid) {
        throw new Error("Invalid or expired password reset token");
    }
    const hash = await bcrypt.hash(password, Number(10));
    await User.updateOne({
        _id: userId
    }, {
        $set: {
            password: hash
        }
    }, {
        new: true
    });
    const user = await User.findById({
        _id: userId
    });
    sendEmail(
        user.email,
        "Password Reset Successfully", {
            name: user.name,
        },
        "./template/resetPassword.handlebars"
    );
    await passwordResetToken.deleteOne();
    return true;
};

module.exports = {
    signup, resetPassword, requestPasswordReset
};