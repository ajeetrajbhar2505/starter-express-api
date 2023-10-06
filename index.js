const express = require("express");
const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
const cors = require("cors");
const dotenv = require("dotenv");
const { v4: uuidv4 } = require("uuid");
const http = require("http");
const { ObjectId } = require("mongodb");
const multer = require("multer");
const path = require("path");
dotenv.config();
app.use(cors());

const fs = require("fs");
const { google } = require("googleapis");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

// Serve static files from the 'public' directory
app.use(express.static(__dirname + "/public"));

// Configure session middleware
app.use(
  require("express-session")({
    secret: process.env.private_key,
    resave: true,
    saveUninitialized: true,
  })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Connection URI
const MongoClient = require("mongodb").MongoClient;
const uri = process.env.mongo_url; // Change this to your MongoDB server URI

const client = new MongoClient(uri);
var database;
async function connectToMongoDB() {
  try {
    database = client.db("class"); // Specify the database name
    if (database) {
      console.log("database connected!");
    }
  } catch (err) {
    console.error("Error connecting to MongoDB:", err);
  }
}

// Authorization function middleware
async function authorizeToken(req, res, next) {
  // Get the token from the request
  if (!req.headers.authorization) {
    return res.sendFile(__dirname + "/public/index.html");
  }
  const token = req.headers.authorization.substring("Bearer ".length);
  if (!token) {
    return res.sendFile(__dirname + "/public/index.html");
  }

  try {
    const tokenExists = await database
      .collection("tokens")
      .findOne({ _id: new ObjectId(token) });
    if (!tokenExists) {
      return res.sendFile(__dirname + "/public/index.html");
    }

    // Continue with the route handling
    next();
  } catch (error) {
    return res.status(401).send("Unauthorized");
  }
}
app.listen(process.env.PORT, connectToMongoDB(), () => {
  console.log("app running fast");
});

app.get("/classDetails", authorizeToken, async (req, res) => {
  let response = await database.collection("classDetails").find({}).toArray();
  if (response) {
    res.send({ status: 200, response: response });
  }
});

app.get("/mostWatched", authorizeToken, async (req, res) => {
  let response = await database.collection("lectureDetails").find({}).toArray();
  if (response) {
    res.send({ status: 200, response: response });
  }
});

app.get("/lectureDetails/:classId", authorizeToken, async (req, res) => {
  const { classId } = req.params;
  let response = await database
    .collection("lectureDetails")
    .find({ classId: classId })
    .toArray();
  if (response) {
    res.send({ status: 200, response: response });
  }
});

app.get(
  "/contentDetails/:classId/:lec_id",
  authorizeToken,
  async (req, res) => {
    const { classId, lec_id } = req.params;
    let response = await database
      .collection("contentDetails")
      .find({ classId: classId, lec_id: lec_id })
      .toArray();
    if (response) {
      res.send({ status: 200, response: response });
    }
  }
);

app.get(
  "/content/:classId/:lec_id/:content_id",
  authorizeToken,
  async (req, res) => {
    const { classId, lec_id, content_id } = req.params;
    let response = await database
      .collection("contentDetails")
      .find({ _id: new ObjectId(content_id) })
      .toArray();
    if (response) {
      res.send({ status: 200, response: response });
    }
  }
);

app.get(
  "/contentDetails",
  authorizeToken,
  async (req, res) => {
    const { classId, lec_id, content_id } = req.params;
    let response = await database
      .collection("contentDetails")
      .find({})
      .toArray();
    if (response) {
      res.send({ status: 200, response: response });
    }
  }
);

// Integrate Server
const server = http.createServer(app);
const { Server } = require("socket.io");
const io = new Server(server);

io.on("connection", (socket) => {
  // Emit a message to the client
  socket.on("message", (msg) => {
    io.emit("message", msg);
  });

  socket.on("notification", (msg) => {
    io.emit("notification", msg);
  });

  socket.on("live", (msg) => {
    io.emit("live", msg);
  });

  socket.on("credentials", (msg) => {
    io.emit("credentials", msg);
  });
});

app.post("/live", authorizeToken, async (req, res) => {
  const { lec_id, live } = req.body;
  let response = await database.collection("contentDetails").updateOne(
    { _id: new ObjectId(lec_id) },
    {
      $set: {
        live: live,
        date: Date(),
      },
    },
    { upsert: true }
  );
  if (response) {
    res.send({ status: 200, message: "Content gone live successfull !" });
  } else {
    res.send({ status: 403, message: "Something went wrong !" });
  }
});

const scope = ["https://www.googleapis.com/auth/drive"];

async function authorize() {
  const jwtClient = new google.auth.JWT(
    process.env.client_email,
    null,
    process.env.private_key,
    scope
  );

  await jwtClient.authorize();

  return jwtClient;
}

// Create the "uploads" directory if it doesn't exist
const uploadDirectory = "files/";

// Function to upload a file to Google Drive
async function uploadFile(authClient, fileInfo) {
  return new Promise((resolve, reject) => {
    const drive = google.drive({ version: "v3", auth: authClient });

    const fileMetaData = {
      name: fileInfo.originalname,
      parents: ["1CBsb1iOv_zEVn3A8JdxiiH3nWOrcUXpI"],
    };

    drive.files.create(
      {
        resource: fileMetaData,
        media: {
          mimeType: fileInfo.mimetype,
          body: fs.createReadStream(`${uploadDirectory + fileInfo.filename}`),
        },
        fields: "id",
      },
      function (err, file) {
        if (err) {
          return reject(err);
        }
        resolve(file);
      }
    );
  });
}

// Configure Multer to specify where to store uploaded files and their names.
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    if (!fs.existsSync(uploadDirectory)) {
      fs.mkdirSync(uploadDirectory);
    }
    cb(null, uploadDirectory); // Specify the directory where files will be stored.
  },
  filename: function (req, file, cb) {
    // Use the current timestamp as a unique file name.
    cb(null, Date.now() + file.originalname);
  },
});

// Configure multer to specify where to store uploaded files
const upload = multer({ storage });

// Route to handle file upload
app.post("/upload", upload.single("file"), authorizeToken, async (req, res) => {
  if (!req.file) {
    return res.status(400).send("No file uploaded.");
  }

  try {
    const authClient = await authorize(); // Implement your authorization logic here
    const uploadedFile = await uploadFile(authClient, req.file);
    const fileId = uploadedFile.data.id;
    const filePath = `https://drive.google.com/file/d/${fileId}/view`;
    const body = { ...req.body, content_link: filePath };
    let response = await database.collection("contentDetails").insertOne(body);
    if (response) {
      res.send({ status: 200, response: "Content uploaded sucessfully" });
    } else {
      res.send({ status: 400, response: "something went wrong" });
    }
  } catch (error) {
    console.error("Error:", error);
    res.status(500).send("An error occurred while uploading the file.");
  }
});

app.post("/upsertContentDetails", authorizeToken, async (req, res) => {});

// Google signup
// Configure Google OAuth Strategy
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.OAuth_client_id,
      clientSecret: process.env.OAuth_Client_secret,
      callbackURL: process.env.OAuth_Callback_url,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        return done(null, profile);
      } catch (error) {
        console.error("Error in Google OAuth strategy:", error);
        return done(error);
      }
    }
  )
);

// Serialize user into the session
passport.serializeUser((profile, done) => {
  done(null, profile);
});

// Deserialize user from the session
passport.deserializeUser((profile, done) => {
  // Retrieve user data from the database based on id.
  // Example: const user = findUserById(id);
  done(null, profile);
});

// Route for Google authentication
app.get(
  "/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/logout", authorizeToken, authorizeToken, async (req, res) => {
  const token = req.headers.authorization.substring("Bearer ".length);
  // Verify if the provided token exists in the "tokens" collection
  const verifyToken = await database
    .collection("tokens")
    .findOne({ _id: new ObjectId(token) });
  let response = await database.collection("users").updateOne(
    { _id: new ObjectId(verifyToken.userId) },
    {
      $set: {
        logged: false,
        date: Date(),
      },
    },
    { upsert: true }
  );
  if (response) {
    res.send({
      status: 200,
      message: `${verifyToken.email} logout successfull !`,
    });
  } else {
    res.send({ status: 403, message: "Something went wrong !" });
  }
});

app.get("/profile", authorizeToken, authorizeToken, async (req, res) => {
  try {
    const token = req.headers.authorization.substring("Bearer ".length);
    // Verify if the provided token exists in the "tokens" collection
    const verifyToken = await database
      .collection("tokens")
      .findOne({ _id: new ObjectId(token) });

    if (verifyToken) {
      // Token is valid; retrieve user data based on the token's userId
      const userId = verifyToken.userId;
      const userResponse = await database
        .collection("users")
        .findOne({ _id: new ObjectId(userId) });

      if (userResponse) {
        // User found; send the user's data in the response
        res.status(200).send({ status: 200, response: userResponse });
      } else {
        // User not found; return a 404 response
        res.status(404).send("User not found");
      }
    } else {
      // Token not valid; return a 404 response
      res.status(404).send("Token not valid");
    }
  } catch (error) {
    // Handle any errors that may occur during database operations
    console.error("Error in /profile route:", error);
    res.status(500).send("Internal Server Error");
  }
});

// Callback route after Google authentication
app.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  async (req, res) => {
    try {
      if (req.isAuthenticated()) {
        // Check if the user exists in the database
        const userExists = await database
          .collection("users")
          .findOne({ email: req.user._json.email });

        if (userExists) {
          await database.collection("users").updateOne(
            { _id: new ObjectId(userExists._id) },
            {
              $set: {
                logged: true,
                date: Date(),
              },
            },
            { upsert: true }
          );
          // User exists, check for an token'
          const response = await database
            .collection("tokens")
            .insertOne({
              userId: userExists._id.toString(),
              email: req.user._json.email,
              dateTime: new Date(),
            });
          return res
            .status(200)
            .redirect(
              "http://localhost:8100/sucessfull/" +
                userExists._id.toString() +
                "/" +
                response.insertedId
            );
        } else {
          // User doesn't exist, create a new user
          const response = await database
            .collection("users")
            .insertOne({ ...req.user._json, logged: true });

          const tokenData = {
            userId: response.insertedId.toString(),
            email: req.user._json.email,
            dateTime: new Date(),
          };

          // Generate a token (assuming you have a function for this)
          const token = await generateToken(tokenData);

          if (!token) {
            // Handle token generation failure
            return res.status(500).send("Token generation failed");
          }

          // Send the token in the response
          return res
            .status(200)
            .redirect(
              "http://localhost:8100/sucessfull/" +
                response.insertedId.toString() +
                "/" +
                token.insertedId
            );
        }
      } else {
        // User is not authenticated, handle accordingly
        return res.status(401).send("User not authenticated");
      }
    } catch (error) {
      // Handle any errors that may occur during token generation or database operations
      console.error("Error in Google callback:", error);
      return res.status(500).send("Internal Server Error");
    }
  }
);

// Function to generate a JWT token (you should implement this)
async function generateToken(tokenData) {
  // Store the token in your database if needed
  try {
    return await database.collection("tokens").insertOne({
      userId: tokenData.userId,
      email: tokenData.email,
      dateTime: tokenData.dateTime,
    });
  } catch (error) {
    throw error;
  }
}
