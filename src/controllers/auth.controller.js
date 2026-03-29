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

  const refreshToken = jwt.sign({ id: user._id }, config.JWT_SECRET, {
    expiresIn: "7d",
  });

  const refreshTokenHash = await bcrypt.hash(refreshToken, 10);

  const session = await sessionModel.create({
    user: user._id,
    refreshTokenHash,
    userAgent: req.headers["user-agent"],
    ip: req.ip,
  });

  const accessToken = jwt.sign({ id: user._id }, config.JWT_SECRET, {
    expiresIn: "15m",
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

// here the access token is generated using the refresh token
export const refreshToken = async (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  if (!refreshToken) {
    return res.status(401).json({ message: "No refresh token found" });
  }

  const decoded = jwt.verify(refreshToken, config.JWT_SECRET);

  // here before generating a new access token we need to check if the refresh token is valid and not revoked
  const refreshTokenHash = await bcrypt.hash(refreshToken, 10);

  const session = await sessionModel.findOne({
    refreshTokenHash,
    revoked: false,
  });

  if (!session) {
    return res.status(401).json({ message: "Invalid refresh token" });
  }

  // if the refresh token is valid and not revoked, we can generate a new access token and a new refresh token
  const accessToken = jwt.sign({ id: decoded.id }, config.JWT_SECRET, {
    expiresIn: "15m",
  });

  const newRefreshToken = jwt.sign({ id: decoded.id }, config.JWT_SECRET, {
    expiresIn: "7d",
  });

  // we also need to update the refresh token in the session model
  const newrefreshTokenHash = await bcrypt.hash(newRefreshToken, 10);
  
  session.refreshTokenHash = newrefreshTokenHash;
  await session.save();

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

  const refreshTokenHash = await bcrypt.hash(refreshToken, 10);

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
