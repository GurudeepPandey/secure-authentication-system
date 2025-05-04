import { Router } from "express";
import { validate } from "../middlewares/validator.middleware.js";
import { isloggedIn } from "../middlewares/auth.middleware.js";
import {
    userRegisterValidation,
    userLoginValidation,
    userForgotPasswordValidation,
    userResetForgotPasswordValidation,
    userChangePasswordValidation
} from "../validators/index.js";
import {
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
} from "../controllers/auth.controllers.js";


const router = Router();


router.route("/register").post(userRegisterValidation(), validate, register);
router.route("/verify-email/:token").post(verificationEmail);
router.route("/login").post(userLoginValidation(), validate, login);
router.route("/refresh-token").get(getRefreshToken);
router.route("/forgot-password").post(userForgotPasswordValidation(), validate, forgotPassword);
router.route("/reset-password/:token").post(userResetForgotPasswordValidation(), validate, resetForgotPassword);

router.route("/user-info").get(isloggedIn, getUserInfo);
router.route("/change-password").post(userChangePasswordValidation(), validate, isloggedIn, changeCurrentPassword);
router.route("/logout").get(isloggedIn, logout);
router.route("/resend-verify-email").post(isloggedIn,resendVerificationEmail);

export default router;