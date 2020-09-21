const express = require("express");
const app = express();
const formidableMiddleware = require("express-formidable");
app.use(formidableMiddleware());
const mongoose = require("mongoose");

// Les packages qui nous permettent l'encryption du mot de passe
const uid2 = require("uid2");
const SHA256 = require("crypto-js/sha256");
const encBase64 = require("crypto-js/enc-base64");

mongoose.connect("mongodb://localhost/user", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

const User = mongoose.model("User", {
  email: String,
  password: String,
});

app.post("/signup", async (req, res) => {
  const salt = uid2(64);
  // le salt va être ajouté au password pour être "hashé"
  //   console.log(salt);
  const hash = SHA256(req.fields.password + salt).toString(encBase64);
  // le hash est le résult de l'encryption du mot de passe + le salt
  // console.log(hash)

  const token = uid2(64);
  // le token va nous servir plus tard, notamment pour vérifier qu'un utilisateur à bien les droits pour effectuer une action donnée (par exemple, poster une annonce sur leboncoin)

  try {
    const newUser = new User({
      email: req.fields.email,
      token: token,
      salt: salt,
      hash: hash,
      username: req.fields.username,
    });
    await newUser.save();
    // dans la réponse que l'on envoie au client, nous faisons attention à n'envoyer que les données nécessaires côté client (donc pas le hash, pas le salt, qui sont des données sensibles)
    res.json({
      _id: newUser._id,
      token: newUser.token,
      email: newUser.email,
      username: newUser.username,
    });
  } catch (error) {
    res.json({ error: error.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    // on cherche le user qui veut se connecter
    const user = await User.findOne({ email: req.fields.email });

    if (user) {
      // si le hash du mot de passe qu'il vient de saisir est le même que le hash enregistré en BDD lors de son inscription, alors c'est bon !
      if (
        SHA256(req.fields.password + user.salt).toString(encBase64) ===
        user.hash
      ) {
        res.json({
          _id: user._id,
          token: user.token,
          email: user.email,
          username: user.username,
        });
      } else {
        // sinon, il n'est pas autorisé à se connecter
        res.json({ error: "Unauthorized" });
      }
    } else {
      res.json({ error: "User not found" });
    }
  } catch (error) {
    res.json({ error: error.message });
  }
});

app.listen(3000, () => {
  console.log("Server Started");
});
