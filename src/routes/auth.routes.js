import { Router } from "express";
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


router.route("/register").post(register);
router.route("/verification-email").post(verificationEmail);
router.route("/resend-verification-email").post(resendVerificationEmail);
router.route("/login").post(login);
router.route("/forgot-password").post(forgotPassword);
router.route("/reset-forgot-password").post(resetForgotPassword);
router.route("/refresh-token").get(getRefreshToken);

router.route("/user-info").get(getUserInfo);
router.route("/logout").get(logout);
router.route("/change-current-password").post(changeCurrentPassword);

export default router;