import { validationResult } from "express-validator";
import { ApiError } from "../utils/api-error.js";

const validate = (req, res, next) => {
    const errors = validationResult(req);
    
    if(errors.isEmpty()) return next();

    const extractedErrors = [];
    errors.array().map(err => extractedErrors.push({
        [err.path]: err.msg
    }));

    const apiError = new ApiError(422, "Validation Error", extractedErrors);

    return res.status(apiError.statusCode).json(apiError.toJSON());
}

export { validate };