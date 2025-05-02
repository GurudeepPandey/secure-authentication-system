import { asyncHandler } from "../utils/async-handler.js";
import { User } from "../models/User.model.js";
import { ApiError } from "../utils/api-error.js";
import { ApiResponse } from "../utils/api-response.js";


const register = asyncHandler(async (req, res) => { 
    return res.status(200).json(
        new ApiResponse(200, { message: "User successfully registered" }, "Successfully get response")
    )
});

const verificationEmail = asyncHandler(async (req, res) => {
    return res.status(200).json(
        new ApiResponse(200, { message: "User successfully verified" }, "Successfully get response")
    )
});

const resendVerificationEmail = asyncHandler(async (req, res) => {
    return res.status(200).json(
        new ApiResponse(200, { message: "Verification email successfully sent" }, "Successfully get response")
    )
});

const login = asyncHandler(async (req, res) => {
    return res.status(200).json(
        new ApiResponse(200, { message: "User successfully logged in" }, "Successfully get response")
    )
});

const getUserInfo = asyncHandler(async (req, res) => {
    return res.status(200).json(
        new ApiResponse(200, { message: "User successfully fetched" }, "Successfully get response")
    )
});

const logout = asyncHandler(async (req, res) => {
    return res.status(200).json(
        new ApiResponse(200, { message: "User successfully logged out" }, "Successfully get response")
    )
});

const forgotPassword = asyncHandler(async (req, res) => {
    return res.status(200).json(
        new ApiResponse(200, { message: "Password reset link successfully sent" }, "Successfully get response")
    )
});

const resetForgotPassword = asyncHandler(async (req, res) => {
    return res.status(200).json(
        new ApiResponse(200, { message: "Password successfully reset" }, "Successfully get response")
    )
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
    return res.status(200).json(
        new ApiResponse(200, { message: "Password successfully changed" }, "Successfully get response")
    )
});

const getRefreshToken = asyncHandler(async (req, res) => {
    return res.status(200).json(
        new ApiResponse(200, { message: "Refresh token successfully fetched" }, "Successfully get response")
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