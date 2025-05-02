import mongoose from "mongoose";
import dotenv from "dotenv";

dotenv.config({
    path: "./.env"
})

const connectDB = async () => {
    try {
        mongoose.connect(process.env.MONGODB_URI);
        console.log("MongoDB Successfully Connected");
        
    } catch (error) {
        console.log("Database connection Failed: ", error);
        process.exit(1);
    }
}

export { connectDB };