import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    refreshTokenHash: {
      type: String,
      required: [true, "refresh token is required"],
    },
    userAgent: {
      type: String,
      required: [true, "user agent is required"],
    },
    ip: {
      type: String,
      required: [true, "IP address is required"],
    },
    revoke: {
      type: Boolean,
      default: false,
    },
  },
  {
    timestamps: true,
  },
);

const sessionModel = mongoose.model("Session", sessionSchema);
export default sessionModel;
