import jwt from "jsonwebtoken";
import { ApiError } from "../utils/api-error.js";
import { User } from "../models/User.model.js";

const isloggedIn = async (req, res, next) => {
    // get access token from cookies
    const token = req.cookies?.accessToken;
    
    // check if access token not exist
    if (!token) {
        return res.status(401).json(
            new ApiError(401, "User need to login or Unauthorised User", []).toJSON()
        )
    }

    // verify access token
    try {
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        const user = await User.findById(decodedToken._id).select(
            "-password -refreshToken -emailVerificationToken -emailVerificationExpiry -forgotPasswordToken -forgotPasswordExpiry"
        )
        if (!user) {
            return res.status(401).json(
                new ApiError(401, "Unauthorised User or User need to login", []).toJSON()
            )
        }

        // add user in request
        req.user = user;

        // call next middleware function
        next();
    } catch (error) {
        return res.status(500).json(
            new ApiError(500, `Internal server error ${error}`, []).toJSON()
        )
    }
}

export { isloggedIn };