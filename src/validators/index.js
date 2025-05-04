import { body } from "express-validator";

const userRegisterValidation = () => {
    return [
        body("username")
            .trim()
            .notEmpty().withMessage("Username is required")
            .isLength({ min: 3 }).withMessage("Username must be at least 3 characters long")
            .isLength({ max: 20 }).withMessage("Username must be at most 20 characters long"),
        body("email")
            .trim()
            .notEmpty().withMessage("Email is required")
            .isEmail().withMessage("Email is not valid"),
        body("password")
            .trim()
            .notEmpty().withMessage("Password is required")
            .isLength({ min: 6 }).withMessage("Password must be at least 6 characters long")
            .isLength({ max: 35 }).withMessage("Password must be at most 35 characters long")
    ]
}

const userLoginValidation = () => {
    return [
        body("email")
            .optional()
            .isEmail().withMessage("Email is invalid")
            .trim()
            .notEmpty().withMessage("Email is required"),
        body("username")
            .optional()
            .trim()
            .notEmpty().withMessage("Username is required")
            .isLength({ min: 3 }).withMessage("Username must be at least 3 characters long")
            .isLength({ max: 20 }).withMessage("Username must be at most 20 characters long"),
        body("password")
            .trim()
            .notEmpty().withMessage("Password is required")
            .isLength({ min: 6 }).withMessage("Password must be at least 6 characters long")
            .isLength({ max: 35 }).withMessage("Password must be at most 35 characters long")
    ]
}

const userForgotPasswordValidation = () => {
    return [
        body("email")
            .trim()
            .notEmpty().withMessage("email is required")
            .isEmail().withMessage("email is invalid")
    ]
}

const userResetForgotPasswordValidation = () => {
    return [
        body("newPassword")
            .trim()
            .notEmpty().withMessage("Password is required")
            .isLength({ min: 6 }).withMessage("Password must be at least 6 characters long")
            .isLength({ max: 35 }).withMessage("Password must be at most 35 characters long"),
        body("confirmPassword")
            .trim()
            .notEmpty().withMessage("Confirm password is required")
            .isLength({ min: 6 }).withMessage("Password must be at least 6 characters long")
            .isLength({ max: 35 }).withMessage("Password must be at most 35 characters long")
    ]
}

const userChangePasswordValidation = () => {
    return [
        body("oldPassword")
            .trim()
            .notEmpty().withMessage("Password is required")
            .isLength({ min: 6 }).withMessage("Password must be at least 6 characters long")
            .isLength({ max: 35 }).withMessage("Password must be at most 35 characters long"),
        body("newPassword")
            .trim()
            .notEmpty().withMessage("Password is required")
            .isLength({ min: 6 }).withMessage("Password must be at least 6 characters long")
            .isLength({ max: 35 }).withMessage("Password must be at most 35 characters long"),
        body("confirmPassword")
            .trim()
            .notEmpty().withMessage("Confirm password is required")
            .isLength({ min: 6 }).withMessage("Password must be at least 6 characters long")
            .isLength({ max: 35 }).withMessage("Password must be at most 35 characters long")
    ]
}

export {
    userRegisterValidation,
    userLoginValidation,
    userForgotPasswordValidation,
    userResetForgotPasswordValidation,
    userChangePasswordValidation
}