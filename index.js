import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
const db = new pg.Client({
  user: "diandrade",
  host: "localhost",
  database: "secrets",
  password: "$89398357",
  port: 5432,
});

//MIDDLEWARE AND DB CONNECT
env.config();
db.connect();
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
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());

//FUNCTIONS
function register(email, password) {
  bcrypt.hash(password, saltRounds, async (err, hash) => {
    if (err) {
      console.log("Error hashing password", err);
    }
    const result = await db.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
      [email, hash]
    );
    const user = result.rows[0];
    return user;
  });
}

async function login(email) {
  const user = await db.query(
    "SELECT * FROM users WHERE LOWER(email) = LOWER($1);",
    [email]
  );
  return user.rows[0];
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

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/register", async (req, res) => {
  try {
    const username = req.body.username;
    const password = req.body.password;
    req.login(register(username, password), (err) => {
      console.log(err);
      res.redirect("/secrets");
    });
  } catch (err) {
    console.log(err);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

passport.use(
  new LocalStrategy(async (username, password, cb) => {
    console.log(username, password);
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

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
