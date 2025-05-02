import express from "express";
import healthCheckRoute from "./routes/healthcheck.routes.js";

const app = express();

app.use(express.json());
app.use(express.urlencoded({extended: true}));
app.use(cors({
    origin: process.env.BASE_URI,
    credentials: true,
    methods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));


app.use("/api/v1/healthcheck", healthCheckRoute);

export default app;