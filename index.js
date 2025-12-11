//import dotenv to loard environment variable
require ('dotenv').config()

//import express
const express=require('express')

//import cors
const cors=require('cors')

//import router
const router=require('./routes')

//import connection.js
require('./connection')

//Create a express server 
//create an express application .the  express() function is a top-level function exported by the express module
const SCPServer=express()

//use of cors -to communicate with view
SCPServer.use(cors())


//use json method -return a middleware which can parse json formate
SCPServer.use(express.json())

//use router
SCPServer.use(router)

//to export upload folder from the serverside to use in th client side
//first argument should the name in which we are using the folder in the client side
//second argument -static method to export the folder 
//static method should have the path of the export folder

SCPServer.use('/uploads',express.static('./uploads'))

//set port for the server
PORT = 4000 || process.env.PORT

//listen to the port -to resolve the request
SCPServer.listen(PORT,()=>{
    console.log(`Server running successfully at port number: ${PORT}`);
})