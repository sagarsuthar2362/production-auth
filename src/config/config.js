import dotenv from "dotenv";
dotenv.config();

const requiredEnvVars = ["MONGO_URI", "JWT_SECRET"];

const missingEnvVars = requiredEnvVars.filter((envVar) => !process.env[envVar]);

if (missingEnvVars.length > 0) {
  console.error(`Missing required env variables: ${missingEnvVars.join(", ")}`);
}

const config = {
  MONGO_URI: process.env.MONGO_URI,
  JWT_SECRET: process.env.JWT_SECRET,
};

export default config;
