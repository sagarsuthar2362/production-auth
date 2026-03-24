import userModel from "../models/user.model.js";
import sessionModel from "../models/session.model.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import config from "../config/config.js";

export const register = async (req, res) => {
  const { username, email, password } = req.body;

  const isAlreadyRegistered = await userModel.findOne({
    $or: [{ username }, { email }],
  });

  if (isAlreadyRegistered) {
    return res
      .status(409)
      .json({ message: "username or email already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await userModel.create({
    username,
    email,
    password: hashedPassword,
  });

  const accessToken = jwt.sign({ id: user._id }, config.JWT_SECRET, {
    expiresIn: "15m",
  });

  const refreshToken = jwt.sign({ id: user._id }, config.JWT_SECRET, {
    expiresIn: "7d",
  });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });

  return res.status(201).json({
    message: "user created succesfully",
    user: {
      username,
      email,
    },
    accessToken,
  });
};

export const getMe = async (req, res) => {
  const token = req.headers.authorization.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "token not found" });
  }

  const decoded = jwt.verify(token, config.JWT_SECRET);

  const user = await userModel.findById(decoded.id);

  return res.status(200).json({
    message: "user fetched succesfully",
    user: {
      username: user.username,
      email: user.email,
    },
  });
};

export const refreshToken = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token found" });
  }

  const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

  const accessToken = jwt.sign({ id: decoded.id }, config.JWT_SECRET, {
    expiresIn: "15m",
  });

  const newRefreshToken = jwt.sign({ id: decoded.id }, config.JWT_SECRET, {
    expiresIn: "7d",
  });

  res.cookie("refreshToken", newRefreshToken, {
    httpOnly: true,
    sameSite: "strict",
    secure: true,
    expiresIn: 7 * 24 * 60 * 60 * 1000,
  });

  res.status(200).json({
    message: "Access token refreshed successfully",
    accessToken,
  });
};

export const logout = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(400).json({ message: "refresh token not found" });
  }

  const session = await sessionModel.findOne({
    refreshTokenHash,
    revoked: false,
  });

  if (!session) {
    return res.status(400).json({ message: "invalid refresh token" });
  }

  session.revoked = true;
  await sessionModel.save();

  res.clearCookie("refreshToken");

  res.status(200).json({ message: "Logged out succesfully" });
};
