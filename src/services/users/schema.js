const { Schema } = require("mongoose");

const UserSchema = new Schema({
    username: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    refreshTokens: [{ token: { type: String } }],
}, { timestamps: true })

module.exports = UserSchema