import crypto from "crypto";
import jwt from "jsonwebtoken";
import { asyncHandler } from "../utils/async-handler.js";
import { User } from "../models/User.model.js";
import { ApiError } from "../utils/api-error.js";
import { ApiResponse } from "../utils/api-response.js";
import { sendMail, emailVerificationMail, forgotPasswordMail } from "../utils/mail.js";
import { UserLoginTypes } from "../constants.js";


const register = asyncHandler(async (req, res) => {
    // get user data
    const { username, email, password } = req.body;

    // check if user already exist
    const existMail = await User.findOne({ email })
    const existUsername = await User.findOne({ username })
    if (existMail || existUsername) {
        return res.status(409).json(
            new ApiError(409, "user already exist with same email or username", []).toJSON()
        )
    }

    // if user not exist then create new user
    const createdUser = await User.create({
        username,
        email,
        password
    })

    // if any error occured during user creation
    if (!createdUser) {
        return res.status(500).json(
            new ApiError(500, "user not created due to internal error", []).toJSON()
        )
    }

    // create email verification token and expiry & save user
    const { unhashedToken, hashedToken, tokenExpiry } = createdUser.generateRandomToken();
    createdUser.emailVerificationToken = hashedToken;
    createdUser.emailVerificationExpiry = tokenExpiry;
    await createdUser.save();

    // send verification email
    try {
        await sendMail({
            email: createdUser.email,
            subject: "Verify your Email",
            mailGenContent: emailVerificationMail(
                createdUser.username,
                `${process.env.BASE_URI}/api/v1/auth/verify-email/${unhashedToken}`
            )
        })
    } catch (error) {
        console.log("Email verification Error: ", error)
        return res.status(500).json(
            new ApiError(500, "verification email not sent due to internal server error", []).toJSON()
        )
    }

    // send success response
    return res.status(201).json(
        new ApiResponse(
            201,
            { message: "user registered successfully and verification email has been sent." },
            "Successfully get response"
        )
    )
});


const verificationEmail = asyncHandler(async (req, res) => {
    // get token
    const { token } = req.params;

    // check if token not exist
    if (!token) {
        return res.status(400).json(
            new ApiError(400, "Verification Token is missing", []).toJSON()
        )
    }

    // hash token for comparison and get user
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");
    const user = await User.findOne({
        emailVerificationToken: hashedToken,
        emailVerificationExpiry: { $gt: Date.now() }
    })
    if (!user) {
        return res.status(400).json(
            new ApiError(400, "Token is expired or invalid", []).toJSON()
        )
    }

    // if user verified then save isEmailVerified as true
    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpiry = undefined;
    await user.save();

    // send success response
    return res.status(200).json(
        new ApiResponse(200, { message: "User email verified" }, "Successfully get response")
    )
});


const login = asyncHandler(async (req, res) => {
    // get data from user request
    const { username, email, password } = req.body;

    // check if username or email is provided
    if (!username && !email) {
        return res.status(400).json(
            new ApiError(400, "username or email is required", []).toJSON()
        )
    }

    // find user based on username or email
    const user = await User.findOne({
        $or: [{ username }, { email }]
    })
    if (!user) {
        return res.status(400).json(
            new ApiError(400, "user not registered with this email or username", []).toJSON()
        )
    }

    // check if user login type is email and password
    if (user.loginType !== UserLoginTypes.EMAIL_PASSWORD) {
        return res.status(400).json(
            new ApiError(400, `You not registered with email and try login with ${user.loginType}`, []).toJSON()
        )
    }

    // check user password is correct
    const isPasswordCorrect = await user.isPasswordCorrect(password);
    if (!isPasswordCorrect) {
        return res.status(400).json(
            new ApiError(400, "password is wrong", []).toJSON()
        )
    }

    // if valid user then generate access and refresh token & save refresh token in DB
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();
    user.refreshToken = refreshToken;
    await user.save();

    // save access and refresh token in cookies
    const options = {
        httpOnly: true,
        secure: true
    }
    res.cookie("accessToken", accessToken, options)
    res.cookie("refreshToken", refreshToken, options)

    // send success response
    return res.status(200).json(
        new ApiResponse(200, { message: "User successfully logged in" }, "Successfully get response")
    )
});


const getRefreshToken = asyncHandler(async (req, res) => {
    // get refresh token
    const incomingRefreshToken = req.cookies.refreshToken;
    if (!incomingRefreshToken) {
        return res.status(400).json(
            new ApiError(400, "Refresh token is missing", []).toJSON()
        )
    }

    try {
        // verify refresh token and find user based on user id in refresh token
        const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
        const user = await User.findById(decodedToken._id);
        if (!user) {
            return res.status(400).json(
                new ApiError(400, "User does not exist", []).toJSON()
            )
        }

        // check if refresh token is same or not
        if (user.refreshToken !== incomingRefreshToken) {
            return res.status(401).json(
                new ApiError(401, "Refresh token is expired or used", []).toJSON()
            )
        }

        // if refresh token is valid then generate access and refresh token & save refresh token in DB
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        user.refreshToken = refreshToken;
        await user.save();

        // save access and refresh token in cookies
        const options = {
            httpOnly: true,
            secure: true
        }
        res.cookie("accessToken", accessToken, options)
        res.cookie("refreshToken", refreshToken, options)

        // send success response
        return res.status(200).json(
            new ApiResponse(200, { message: "Refresh token successfully sent" }, "Successfully get response")
        )
    } catch (error) {
        // send error response
        return res.status(500).json(
            new ApiError(500, `Internal server error ${error}`, []).toJSON()
        )
    }
});


const forgotPassword = asyncHandler(async (req, res) => {
    // get email from user request
    const { email } = req.body;

    // find user based on email
    const user = await User.findOne({ email })
    if (!user) {
        return res.status(400).json(
            new ApiError(400, "user not exist or registered with this email", []).toJSON()
        )
    }

    // create email verification token and expiry & save user
    const { unhashedToken, hashedToken, tokenExpiry } = user.generateRandomToken();
    user.forgotPasswordToken = hashedToken;
    user.forgotPasswordExpiry = tokenExpiry;
    await user.save();

    // send verification email
    try {
        await sendMail({
            email: user.email,
            subject: "Reset Yout Password",
            mailGenContent: forgotPasswordMail(
                user.username,
                `${process.env.BASE_URI}/api/v1/auth/reset-password/${unhashedToken}`
            )
        })
    } catch (error) {
        console.log("Forgot password Email Error: ", error)
        return res.status(500).json(
            new ApiError(500, "verification email not sent due to internal server error", []).toJSON()
        )
    }

    // send success response
    return res.status(200).json(
        new ApiResponse(200, { message: "Password reset link successfully sent to your email." }, "Successfully get response")
    )
});


const resetForgotPassword = asyncHandler(async (req, res) => {
    // get token from url, new password and confirm password and validate
    const { token } = req.params;
    const { newPassword, confirmPassword } = req.body;
    if (!token) {
        return res.status(400).json(
            new ApiError(400, "Reset Password Token is missing", []).toJSON()
        )
    }
    if (newPassword !== confirmPassword) {
        return res.status(400).json(
            new ApiError(400, "New Passwords are not matching", []).toJSON()
        )
    }

    // hash token for comparison
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    // find user based on hashed token
    const user = await User.findOne({
        forgotPasswordToken: hashedToken,
        forgotPasswordExpiry: { $gt: Date.now() }
    })
    if (!user) {
        return res.status(400).json(
            new ApiError(400, "Token is expired or invalid", []).toJSON()
        )
    }

    // update user password
    user.forgotPasswordToken = undefined;
    user.forgotPasswordExpiry = undefined;
    user.password = confirmPassword;
    await user.save();

    // send success response
    return res.status(200).json(
        new ApiResponse(200, { message: "Password reset successfully" }, "Successfully get response")
    )
});


const getUserInfo = asyncHandler(async (req, res) => {
    // directly send user info from req to res
    return res.status(200).json(
        new ApiResponse(200, req.user, "Successfully get response")
    )
});


const changeCurrentPassword = asyncHandler(async (req, res) => {
    // get old password, new password and confirm password and validate
    const { oldPassword, newPassword, confirmPassword } = req.body;
    if (newPassword !== confirmPassword) {
        return res.status(400).json(
            new ApiError(400, "New Passwords are not matching", []).toJSON()
        )
    }

    // get user and check old password is correct or not
    const user = await User.findById(req.user._id);
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword);
    if (!isPasswordCorrect) {
        return res.status(400).json(
            new ApiError(400, "Old Password is incorrect", []).toJSON()
        )
    }

    // update user password
    user.password = confirmPassword;
    await user.save();

    // send success response
    return res.status(200).json(
        new ApiResponse(200, { message: "Password successfully changed" }, "Successfully get response")
    )
});


const logout = asyncHandler(async (req, res) => {
    // update user refresh token
    await User.findByIdAndUpdate(
        req.user._id,
        { $set: { refreshToken: '' } },
        { new: true }
    );

    // clear cookies
    const options = {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
    };
    res.clearCookie("accessToken", options)
    res.clearCookie("refreshToken", options)

    // send success response
    return res.status(200).json(
        new ApiResponse(200, { message: "User logged out" }, "Successfully get response")
    )
});


const resendVerificationEmail = asyncHandler(async (req, res) => {
    // get user 
    const user = await User.findById(req.user._id);
    if (!user) {
        return res.status(409).json(
            new ApiError(409, "User does not exists", []).toJSON()
        )
    }

    // check if email is already verified
    if (user.isEmailVerified) {
        return res.status(409).json(
            new ApiError(409, "Email is already verified!", []).toJSON()
        )
    }
    
    // create email verification token and expiry & save user
    const { unhashedToken, hashedToken, tokenExpiry } = user.generateRandomToken();
    user.emailVerificationToken = hashedToken;
    user.emailVerificationExpiry = tokenExpiry;
    await user.save();

    // send verification email
    try {
        await sendMail({
            email: user.email,
            subject: "Verify your Email",
            mailGenContent: emailVerificationMail(
                user.username,
                `${process.env.BASE_URI}/api/v1/auth/verify-email/${unhashedToken}`
            )
        })
    } catch (error) {
        console.log("Email verification Error: ", error)
        return res.status(500).json(
            new ApiError(500, "verification email not sent due to internal server error", []).toJSON()
        )
    }

    // send success response
    return res.status(200).json(
        new ApiResponse(
            200,
            { message: "Verification email has been sent." },
            "Successfully get response"
        )
    )
});

export {
    register,
    verificationEmail,
    resendVerificationEmail,
    login,
    getUserInfo,
    logout,
    forgotPassword,
    resetForgotPassword,
    changeCurrentPassword,
    getRefreshToken
}