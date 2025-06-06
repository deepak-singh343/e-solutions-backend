const express = require("express");
const router = express.Router();
const { db, admin } = require("../firebase");
const nodemailer = require("nodemailer");

const OTP_EXPIRATION_MINUTES = 5;
const transporter = nodemailer.createTransport({
  service: "Gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

router.post("/send-otp", async (req, res) => {
  const { email, userType } = req.body;
  const otp = generateOtp();
  const expiresAt = Date.now() + OTP_EXPIRATION_MINUTES * 60000;

  try {
    const existingDoc = await db.collection("email-otps").doc(email).get();

    if (existingDoc.exists) {
      const existingData = existingDoc.data();

      if (existingData.userType !== userType) {
        return res.status(400).json({
          message: `This email is already registered as a '${existingData.userType}'. You can't use it as '${existingData.userType}'.`,
        });
      }
    }

    await db
      .collection("email-otps")
      .doc(email)
      .set({ otp, expiresAt, userType });

    await transporter.sendMail({
      from: `"Deepak Singh Dashboard App" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Your OTP Code for signing into dashboard",
      html: `<h3>Your OTP is <strong>${otp}</strong></h3><p>It will expire in ${OTP_EXPIRATION_MINUTES} minutes.</p>`,
    });

    res.status(200).json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Failed to send OTP" });
  }
});

router.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;

  try {
    const doc = await db.collection("email-otps").doc(email).get();

    if (!doc.exists)
      return res.status(400).json({ message: "Invalid request" });

    const data = doc.data();

    if (Date.now() > data.expiresAt)
      return res.status(400).json({ message: "OTP expired" });

    if (otp !== data.otp)
      return res.status(400).json({ message: "Incorrect OTP" });

    const token = await admin.auth().createCustomToken(email);

    res.status(200).json({ token, userType: data.userType });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Verification failed" });
  }
});

module.exports = router;
