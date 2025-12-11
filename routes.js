//1)import express
const express = require('express')
//import userController file
const userController = require('./controller/userController')

//import jwtmidddleware
const jwt = require('./middleware/jwtMiddleware')
const adminjwt = require('./middleware/adminMiddleware')
const multerConfig = require('./middleware/multerMiddleware')

//2)create an object for router class
const router = new express.Router()

//3)set up path for each request from view

//register request
router.post('/register', userController.registerController)

//login 
router.post('/login', userController.loginController)

//user-only route (needs login)
router.get('/dashboard', jwt, (req, res) => {
  res.json({ message: "Welcome User", user: req.user })
})

//admin-only route (needs login + admin role)
router.get('/admin-dashboard', jwt, adminjwt, (req, res) => {
  res.json({ message: "Welcome Admin", user: req.user })
})


//forgot password Api
router.post("/send-otp",userController.sendOtpController);
router.post("/verify-otp", userController.verifyOtpController);
router.post("/reset-password", userController.resetPasswordController);

//edit profile
router.put("/update-profile",multerConfig.single('profile'),jwt,userController.editProfileController)
// router.put("/update-profile", jwt, upload.none(), userController.editProfileController);
// //edit profile example (protected)
// router.put('/edit-profile', jwt, multerConfig.single('profile'), userController.editProfileController)

//getprofileInfo
router.get('/profile-info',jwt,userController.profileInfoController)


//4)export the router
module.exports = router
