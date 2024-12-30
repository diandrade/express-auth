import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import GoogleStrategy from "passport-google-oauth20";
import { Strategy as LocalStrategy } from "passport-local";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();
const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});

//MIDDLEWARE AND DB CONNECT
db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

//FUNCTIONS
async function register(email, password) {
  try {
    const hash = await bcrypt.hash(password, saltRounds);
    const result = await db.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
      [email, hash]
    );
    return result.rows[0];
  } catch (err) {
    console.error("Error in register function:", err);
    throw err;
  }
}

async function login(email) {
  const user = await db.query(
    "SELECT * FROM users WHERE LOWER(email) = LOWER($1);",
    [email]
  );
  return user.rows[0];
}

async function userInputSecret(userSecret, email) {
  try {
    await db.query("UPDATE users SET secret = $1 WHERE email = $2", [
      userSecret,
      email,
    ]);
  } catch (err) {
    console.error("Error updating secret in database:", err);
    throw err;
  }
}

async function userSecretSearch(email) {
  try {
    const result = await db.query("SELECT secret FROM users WHERE email = $1", [
      email,
    ]);
    return result.rows.length > 0 ? result.rows[0].secret : null;
  } catch (err) {
    console.error("Error searching for secret in database:", err);
    throw err;
  }
}

//HTTP REQ
app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/submit", (req, res) => {
  res.render("submit.ejs");
});

app.get("/secrets", async (req, res) => {
  const defaultSecret = "Submit your Secret pressing the button above.";
  const userSecret = await userSecretSearch(req.user.email);
  if (req.isAuthenticated()) {
    res.render("secrets.ejs", {
      secret: userSecret || defaultSecret,
    });
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/");
  });
});

app.post("/register", async (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;
    const user = await register(username, password);
    req.login(user, (err) => {
      if (err) {
        console.error(err);
        return res.redirect("/register");
      }
      res.redirect("/secrets");
    });
  } catch (err) {
    console.error(err);
    res.redirect("/register");
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/submit", async (req, res) => {
  const userSecret = req.body.secret;
  console.log(userSecret);

  if (req.isAuthenticated()) {
    const email = req.user.email;
    try {
      await userInputSecret(userSecret, email);
      res.redirect("/secrets");
    } catch (err) {
      console.error("Error saving secret:", err);
      res.status(500).send("An error occurred while submitting your secret.");
    }
  } else {
    res.redirect("/login");
  }
});

passport.use(
  "local",
  new LocalStrategy(async (username, password, cb) => {
    try {
      if (!username || !password) {
        return cb(null, false, {
          message: "Username and password are required.",
        });
      }
      const user = await login(username);
      if (!user) {
        return cb(null, false, { message: "User not found" });
      }
      const hash = user.password;
      const isMatch = await bcrypt.compare(password, hash);
      if (!isMatch) {
        return cb(null, false, { message: "Invalid credentials" });
      }
      return cb(null, user);
    } catch (err) {
      console.error(err);
      return cb(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (acessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.emails[0].value,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.emails[0].value, "google"]
          );
          cb(null, newUser.rows[0]);
        } else {
          cb(null, result.rows[0]);
        }
      } catch (err) {
        cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
