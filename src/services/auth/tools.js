const jwt = require("jsonwebtoken")
const UserSchema = require("../users/schema")
const UserModel = require("mongoose").model("User", UserSchema)

const authenticate = async user => {
  try {
    const accessToken = await generateJWT({ _id: user._id })
    const refreshToken = await generateRefreshJWT({ _id: user._id })

    user.refreshTokens = user.refreshTokens.concat({ token: refreshToken })
    console.log(user.refreshTokens,"----------")
    await user.save()

    return { accessToken,refreshToken }
  } catch (error) {
    console.log(error)
    throw new Error(error)
  }
}

const generateJWT = payload =>
  new Promise((res, rej) =>
    jwt.sign(
      payload,
      process.env.JWT_SECRET,
      { expiresIn: "15 min" },
      (err, token) => {
        if (err) rej(err)
        res(token)
      }
    )
  )

const verifyJWT = token =>
  new Promise((res, rej) =>
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) rej(err)
      res(decoded)
    })
  )

const generateRefreshJWT = payload =>
  new Promise((res, rej) =>
    jwt.sign(
      payload,
      process.env.REFRESH_JWT_SECRET,
      { expiresIn: "1 week" },
      (err, token) => {
        if (err) rej(err)
        res(token)
      }
    )
  )

const verifyRefreshToken = token =>
  new Promise((res, rej) =>
    jwt.verify(token, process.env.REFRESH_JWT_SECRET, (err, decoded) => {
      if (err) rej(err)
      res(decoded)
    })
  )

const refreshToken = async oldRefreshToken => {
  const decoded = await verifyRefreshToken(oldRefreshToken)

  const user = await UserModel.findOne({ _id: decoded._id })

  if (!user) {
    throw new Error(`Access is forbidden`)
  }
  const currentRefreshToken = user.refreshTokens.find(
    t => t.token === oldRefreshToken
  )

  if (!currentRefreshToken) {
    throw new Error(`Refresh token is wrong`)
  }

  const newAccessToken = await generateJWT({ _id: user._id })
  const newRefreshToken = await generateRefreshJWT({ _id: user._id })

  const newRefreshTokens = user.refreshTokens
    .filter(t => t.token !== oldRefreshToken)
    .concat({ token: newRefreshToken })

  user.refreshTokens = [...newRefreshTokens]

  await user.save()

  return { accessToken: newAccessToken, refreshToken: newRefreshToken }
}

module.exports = { authenticate, verifyJWT, refreshToken }
