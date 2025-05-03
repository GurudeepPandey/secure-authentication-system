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

export {
    userRegisterValidation
}