const router = require("express").Router()
const { authenticate } = require("../auth/tools")
const UserSchema = require("./schema")
const UserModel = require("mongoose").model("User", UserSchema)

router.post("/register", async (req, res) => {
    try {
        const { username, password } = req.body
        if (!username || !password) throw new Error("Provide credentials")

        const user = new UserModel({ username, password })
        const { _id } = await user.save()

        res.status(201).send({ _id })

    } catch (error) {
        res.status(400).send({
            message: error.message,
            errorCode: 'wrong_credentials'
        })
    }
})

router.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body
        if (!username || !password) throw new Error("Provide credentials")

        const user = await UserModel.findOne({ username })
        const tokens = await authenticate(user)
        user.password === password
            ? res.status(200).send({ tokens,user })
            : res.status(400).send({ message: "No username/password match" })

    } catch (error) {
        res.status(400).send({
            message: error.message,
            errorCode: 'wrong_credentials'
        })
    }
})


module.exports = router