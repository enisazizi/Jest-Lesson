const jwt = require("jsonwebtoken")
const UserSchema = require("../users/schema")
const UserModel = require("mongoose").model("User", UserSchema)

const { verifyJWT } = require("./tools")

const authorize = async(req,res,next)=>{
    try { 
        const token = req.header("Authorization").replace("Bearer ","")
        const decoded = await verifyJWT(token)
        const user = await UserModel.findOne({
            _id:decoded._id
        })

        if(user){
            req.token = token 
            req.user = user
            next()
        }else{
            throw new Error("middleware error")
        }
        
    } catch (error) {
        const err = new Error("please authenticate")
        err.httpStatusCode = 401 
        next(err)
    }
}

module.exports = {authorize}