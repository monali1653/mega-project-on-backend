 // will verify if user is there or not

import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"
import { User } from "../models/user.model.js";

 export const verifyJWT = asyncHandler(async(req, _, next) => {
    try {
        const token = req.cookies?.accessToken || req.header("Authorization")?.replace("Bearer ", "")
    
        if(!token) {
            throw new ApiError(401, "Unauthorized request")
        }
    
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET)  //token is verified
    
        const user = await User.findById(decodedToken?._id).select("-password -refreshToken")  //fetch user information from database using _id from decoded token
        if(!user) {
            throw new ApiError(401, "Invalid Access Token")
        }
    
        req.user = user; //user info is attached to the req object so that subsequent middlewares or route handlers can access the authenticated users data
        next() // this fn is called to pass control to the next middleware or route handler
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid Access Token")
    }

 })


 
 // The verifyJWT middleware ensures that:

//The request contains a valid JWT.
//The JWT is verified using a secret key.
//The corresponding user exists in the database.
//If the token and user are valid, the user's information is attached to the request for further use in subsequent handlers.