import jwt from "jsonwebtoken";
import { ApiError } from "../utils/api-error.js";
import { User } from "../models/User.model.js";

const userIsloggedIn = async (req, res, next) => {
    const token = req.cookies?.accessToken;
    if (!token) {
        return res.status(401).json(
            new ApiError(401, "Token not found or unauthorised user", []).toJSON()
        )
    }

    try {
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        const user = await User.findById(decodedToken._id);
        if (!user) {
            return res.status(401).json(
                new ApiError(401, "Unauthorised User or User need to login", []).toJSON()
            )
        }
        req.user = user;
        next();
    } catch (error) {
        return res.status(500).json(
            new ApiError(500, `Internal server error ${error}`, []).toJSON()
        )
    }
}

export { userIsloggedIn };