import { Router } from "express";
import { userRegisterValidation } from "../validators/index.js";
import { validate } from "../middlewares/validator.middleware.js";
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
router.route("/resend-verify-email").post(resendVerificationEmail);
router.route("/login").post(login);
router.route("/forgot-password").post(forgotPassword);
router.route("/reset-forgot-password").post(resetForgotPassword);
router.route("/refresh-token").get(getRefreshToken);

router.route("/user-info").get(getUserInfo);
router.route("/logout").get(logout);
router.route("/change-current-password").post(changeCurrentPassword);

export default router;