const express = require("express");
const models = require("./models");
const cors = require("cors");
const app = express();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const cookieParser = require("cookie-parser");
const FacebookStrategy = require("passport-facebook").Strategy;
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GithubStrategy = require("passport-github2").Strategy;
const LocalStrategy = require("passport-local").Strategy;
const User = require("./models");
const session = require("express-session");
var connect = require("connect");
const sequelize = require("sequelize");
const {where, Op} = require("sequelize");
var flash = require("flash");
var passport = require("passport");
const JwtStrategy = require("passport-jwt").Strategy,
ExtractJwt = require("passport-jwt").ExtractJwt;
const { v4: uuidv4 } = require("uuid"); // uuid, To call: uuidv4();
require("dotenv").config();
const opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = process.env.JWT_SECRET_KEY;
const salt = 10;
require("dotenv").config();
app.use(
    cors({
        origin: "*",
        methods: "GET, POST, PATCH, DELETE, PUT",
        allowedHeaders: "Content-Type, Authorization"
    })
);
//app.use(cors());
app.use(express.json());

app.use(
    session({
        genid: function (req) {
            return uuidv4();
        },
        secret: "SECRET",
        resave: false,
        saveUninitialized: true,
        cookie: { maxAge: 60 * 60 * 1000, secure: true } // 1 hour - set to true to only allow https
    })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());

//***************************REGISTRATION***************************//

app.post("/api/register", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const persistedUser = await models.Users.findOne({
        where:{
            name : sequelize.where(sequelize.fn('LOWER', sequelize.col('name')),{
                [Op.like]:username.toLowerCase()
            })
        }
    })
    if (persistedUser == null) {
        bcrypt.hash(password, salt, async (error, hash) => {
            console.log(hash)
            if (error) {
                res.json({ message: "Something Went Wrong!!!" })
            } else {
                const user = models.Users.build({
                    name: username,
                    password: hash,
                    high_score: "0"
                })
                let savedUser = await user.save()
                if (savedUser != null) {
                    res.json({ success: true })
                }
            }
        })
    } else {
        res.json({ message: "That name is taken." })
    }
})
//***************************LOGIN PAGE***************************//

app.post("/api/login", async (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const user = await models.Users.findOne({
        where:{
            name : sequelize.where(sequelize.fn('LOWER', sequelize.col('name')),{
                [Op.like]:username.toLowerCase()
            })
        }
    });
    if (user != null) {
        bcrypt.compare(password, user.password, (error, result) => {
            if (result) {
                const token = jwt.sign({ name: username }, process.env.JWT_SECRET_KEY);
                res.json({
                    success: true,
                    token: token,
                    name: username,
                    high_score: user.high_score,
                    user_id: user.id
                });
            } else {
                res.json({ success: false, message: "You Shall Not Pass" });
            }
        });
    } else {
        res.json({ message: "That is not your username" });
    }
});


// app.post("/api/login", passport.authenticate("local",function(req, res) {
//   // If this function gets called, authentication was successful.
//   // To Access specific user info use- req.user.high_score
//   console.log("User was Authenticated")
//   //successRedirect: "https://quizwiz.me"

// }));

// passport.use(
//   new LocalStrategy(async function(username, password, done) {

//     const user = await models.Users.findOne({
//         where: {
//             name: username
//         }
//     })
//     if (user != null) {
//     bcrypt.compare(password,user.password, (error, result) => {
//       if (result) {
//         const token = jwt.sign({ name: username }, process.env.JWT_SECRET_KEY);
//         return done(null,
//           username
//         )
//       } else {
//         return done(console.log( "Not Authenticated" ))
//       }
//     })
//   } else {
//     return done({ message: "Username Incorrect" })
//   }
//     }))

//*******************Serialize User***********************//

passport.serializeUser(function (user, done) {
    console.log("user.id from serializeUser", user.id), done(null, user.id);
});

passport.deserializeUser(function (id, done) {
    //models.Users.findById(id, function(err, user) {
    done(null, id);
    // });
});

//*******************  Google Strategy  ***********************//

app.get(
    "/auth/google",
    passport.authenticate("google", { scope: ["profile"] })
);
app.get(
    "/auth/google/callback",
    passport.authenticate("google", {
        failureRedirect: "https://quizwiz.surge.sh"
    }),
    function (req, res) {
        res.redirect("https://quizwiz.surge.sh/profile/" + req.user.displayName);
    }
);
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: "https://damp-spire-28696.herokuapp.com/auth/google/callback"
        },
        async function (request, accessToken, refreshToken, profile, done) {
            //     return done(null, profile,
            //       console.log(JSON.stringify(profile), 'AccessToken:', accessToken, 'Refresh Token:', refreshToken))
            //   }
            // ));

            const name = profile.displayName;
            const password = profile.id;
            const token = profile.accessToken;

            const persistedUser = await models.Users.findOne({
                where: {
                    name: name
                }
            });

            if (persistedUser == null) {
                console.log("user");
                bcrypt.hash(password, salt, async (error, hash) => {
                    console.log(hash);
                    if (error) {
                        res.json({ message: "Something Went Wrong!!!" });
                    } else {
                        const user = models.Users.build({
                            name: name,
                            password: hash,
                            high_score: "0"
                        });

                        let savedUser = await user.save();
                        if (savedUser != null) {
                            console.log("{ success: true }");

                            //res.json(profile);
                            return done(
                                null,
                                profile,
                                console.log("new user was added by passport")
                            );
                        }
                    }
                });
            } else {
                console.log('res.json({ message: "Existing User" })');
                return done(
                    null,
                    profile,

                    console.log("existing user was authenticated")
                );
            }
        }
    )
);
//*******************  Facebook Strategy  ***********************//

app.get("/auth/facebook", passport.authenticate("facebook"));
app.get(
    "/auth/facebook/callback",
    passport.authenticate("facebook", {
        failureRedirect: "https://quizwiz.surge.sh"
    }),
    function (req, res) {
        res.redirect("https://quizwiz.surge.sh/profile/" + req.user.displayName);
    }
);
passport.use(
    new FacebookStrategy(
        {
            clientID: process.env.FACEBOOK_CLIENT_ID,
            clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
            callbackURL: "https://damp-spire-28696.herokuapp.com/auth/facebook/callback"
        },
        async function (accessToken, refreshToken, profile, done) {
            //     return done(null, profile,
            //       console.log(JSON.stringify(profile), 'AccessToken:', accessToken, 'Refresh Token:', refreshToken))
            //   }
            // ));

            const name = profile.displayName;
            const password = profile.id;
            const token = profile.accessToken;

            const persistedUser = await models.Users.findOne({
                where: {
                    name: name
                }
            });

            if (persistedUser == null) {
                console.log("user");
                bcrypt.hash(password, salt, async (error, hash) => {
                    console.log(hash);
                    if (error) {
                        res.json({ message: "Something Went Wrong!!!" });
                    } else {
                        const user = models.Users.build({
                            name: name,
                            password: hash,
                            spare_one: token,
                            high_score: "0"
                        });

                        let savedUser = await user.save();
                        if (savedUser != null) {
                            console.log("{ success: true }");
                            return done(
                                null,
                                profile,
                                console.log(
                                    JSON.stringify(profile),
                                    "AccessToken:",
                                    accessToken,
                                    "Refresh Token:",
                                    refreshToken
                                )
                            );
                        }
                    }
                });
            } else {
                console.log(
                    'res.json({ message: " Sorry This UserName Already Exists." })'
                );
                return done(
                    null,
                    profile,
                    console.log(
                        JSON.stringify(profile),
                        "AccessToken:",
                        accessToken,
                        "Refresh Token:",
                        refreshToken
                    )
                );
            }
        }
    )
);

//*******************  Github Strategy  ***********************//

app.get("/auth/github", passport.authenticate("github"));
app.get(
    "/auth/github/callback",
    passport.authenticate("github", {
        failureRedirect: "https://quizwiz.surge.sh"
    }),
    function (req, res) {
        res.redirect("https://quizwiz.surge.sh/profile/" + req.user.username);
    }
);

passport.use(
    new GithubStrategy(
        {
            clientID: process.env.GITHUB_CLIENT_ID,
            clientSecret: process.env.GITHUB_CLIENT_SECRET,
            callbackURL: "https://damp-spire-28696.herokuapp.com/auth/github/callback"
        },
        async function (accessToken, refreshToken, profile, done) {
            //     return done(null, profile,
            //       console.log(JSON.stringify(profile), 'AccessToken:', accessToken, 'Refresh Token:', refreshToken))
            //   }
            // ));

            const name = profile.username;
            const password = profile.id;
            const token = profile.accessToken;

            const persistedUser = await models.Users.findOne({
                where: {
                    name: name
                }
            });

            if (persistedUser == null) {
                console.log("user");
                bcrypt.hash(password, salt, async (error, hash) => {
                    console.log(hash);
                    if (error) {
                        //res.json({ message: "Something Went Wrong!!!" })
                    } else {
                        const user = models.Users.build({
                            name: name,
                            password: hash,
                            spare_one: token,
                            high_score: "0"
                        });

                        let savedUser = await user.save();
                        if (savedUser != null) {
                            console.log("{ success: true }");
                            return done(
                                null,
                                profile,
                                console.log(
                                    JSON.stringify(profile),
                                    "AccessToken:",
                                    accessToken,
                                    "Refresh Token:",
                                    refreshToken
                                )
                            );
                        }
                    }
                });
            } else {
                console.log(
                    'res.json({ message: " Sorry This UserName Already Exists." })'
                );
                return done(
                    null,
                    profile,
                    console.log(
                        JSON.stringify(profile),
                        "AccessToken:",
                        accessToken,
                        "Refresh Token:",
                        refreshToken
                    )
                );
            }
        }
    )
);

//*************LOGOUT**********//

app.get("/logout", function (req, res) {
    req.logout();
    res.redirect("/");
});

//***************************LeaderBoard***************************//

app.get("/api/highscore", (req, res) => {
    let leaderboard = [];
    let users = models.Users.findAll({
        raw: true,
        limit: 99,
        group: ["high_score", "Users.id"],
        order: [[sequelize.fn("max", sequelize.col("high_score")), "DESC"]]
        //  [['score', 'Desc']]
    }).then(high_Score => {
        let len = high_Score.length
        console.log(high_Score.length)
        for (let i = 0; i < len; i++) {
            leaderboard.push({
                username: high_Score[i]["name"],
                score: high_Score[i]["high_score"]
            });
        }
        res.json(leaderboard);
    });
});

//***************************Users HIGH SCORE***************************//

app.get("/api/userscore", async (req, res) => {
    let username = req.query["username"];
    let userScore = null;
    let score = await models.Users.findOne({
        where: {
            name: username
        }
    }).then(user_Score => {
        console.log(user_Score["dataValues"]["high_score"]);
        userScore = user_Score["dataValues"]["high_score"];
    });
    res.json({ score: userScore });
});

//***************************Get questions***************************//

app.get("/quiz/:category", (req, res) => {
    let category = req.params["category"];
    if (category == 100) {
        axios
            .get(
                `https://opentdb.com/api.php?amount=13&difficulty=easy&type=multiple`
            )
            .then(response => response.data)
            .then(result => {
                console.log(results.results);
                res.json(result.results);
            });
    } else {
        axios
            .get(
                `https://opentdb.com/api.php?amount=13&category=${category}&difficulty=easy&type=multiple`
            )
            .then(response => response.data)
            .then(result => {
                res.json(result.results);
            });
    }
});
//**************************Delete user**************************//

//localstorage.clear on users end as well
app.post("/api/deleteuser", async (req, res) => {
    console.log(req.body[0].userName);
    let user = await models.Users.destroy({
        where: {
            name: req.body[0].userName
        }
    }).then(removeduser => {
        console.log(`removed ${req.body[0].userName}`);
        res.send(`removed ${req.body[0].userName}`);
    });
});

//**************************Submit Score**************************//

app.post("/api/submit", async (req, res) => {
    let user = await models.Users.findOne({
        where: {
            name: req.body.username
        }
    });
    console.log("user high score", user["high_score"] )
    console.log("req.body.score", req.body.score )
    if (user["high_score"] < req.body.score) {
        models.Users.update(
            { high_score: req.body.score },
            { where: { name: req.body.username } }
        ).then(result => {
            res.send({ newHighScore : true });
        });
    } else {
        res.send({ newHighScore : false });
    }
});

//**************************Server Hosting**************************//

//app.listen( process.env.PORT);
app.listen(8080, () => {
    console.log("Server is running...");
});