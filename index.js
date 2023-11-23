const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const app = express();
const port = process.env.PORT || 5000;
const CryptoJS = require("crypto-js");

// encryption and decryption
const encodeFn = (data) => {
  const cipherText = CryptoJS.AES.encrypt(
    JSON.stringify(data),
    process.env.SECRET_KEY
  ).toString();
  return cipherText;
};

const decodedFn = (data) => {
  const bytes = CryptoJS.AES.decrypt(data, process.env.SECRET_KEY);
  const decryptedData = JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
  return decryptedData;
};

// middleware
app.use(
  cors({
    origin: [
      "http://localhost:3000",
      "https://job-seeker-2064e.web.app",
      "https://job-seeker-2064e.firebaseapp.com",
    ],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.hixyzlt.mongodb.net/?retryWrites=true&w=majority`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

const verifyToken = (req, res, next) => {
  const token = req?.cookies?.token;
  // console.log("token in the middleware", token);
  if (!token) {
    return res.status(401).send({ message: "unauthorized access" });
  }
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).send({ message: "unauthorized access" });
    }
    req.user = decoded;
    next();
  });
};

async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    // await client.connect();

    const jobCollection = client.db("job-seekers").collection("jobs");
    const seekersCollection = client.db("job-seekers").collection("seekers");
    const usersCollection = client.db("job-seekers").collection("users");

    // auth related api
    app.post("/jwt", async (req, res) => {
      const user = req.body;
      console.log("user for token: ", user);
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "1h",
      });
      res
        .cookie("token", token, {
          httpOnly: true,
          secure: true,
          sameSite: "none",
        })
        .send({ success: true });
    });

    app.post("/logout", async (req, res) => {
      const user = req.body;
      console.log("logout user", user);
      res.clearCookie("token", { maxAge: 0 }).send({ success: true });
    });

    // users api
    app.get("/user", async (req, res) => {
      const email = req.query.email;
      const result = await usersCollection.findOne({ email });
      result.password = decodedFn(result.password);
      result.role = decodedFn(result.role);
      res.send(result);
    });

    app.post("/registration", async (req, res) => {
      let data = req.body;
      data.password = encodeFn(data.password);
      data.role = encodeFn(data.role);
      const result = await usersCollection.insertOne(data);
      res.send(result);
    });

    //job apis
    app.get("/jobs", async (req, res) => {
      const result = await jobCollection.find({}).toArray();
      res.send(result);
    });

    app.get("/jobs/:id", async (req, res) => {
      const id = req.params;
      const result = await jobCollection.findOne({ _id: new ObjectId(id) });
      res.send(result);
    });

    app.get("/jobFilter", verifyToken, async (req, res) => {
      if (req.query.email !== req.user.email) {
        return res.status(403).send({ message: "forbidden access" });
      }
      let query = {};
      if (req.query?.email) {
        query = { userEmail: req.query.email };
      }
      const result = await jobCollection.find(query).toArray();
      res.send(result);
    });

    app.post("/jobs", verifyToken, async (req, res) => {
      const data = req.body;
      if (data.userEmail !== req.user.email) {
        return res.status(403).send({ message: "forbidden access" });
      }
      const result = await jobCollection.insertOne(data);
      console.log(result);
      res.send(result);
    });

    app.delete("/deleteJob/:id", async (req, res) => {
      const id = req.params;
      const result = await jobCollection.deleteOne({ _id: new ObjectId(id) });
      const deleteSeeker = await seekersCollection.deleteMany({ jobId: id.id });
      res.send(result);
    });

    app.patch("/updatePost/:id", async (req, res) => {
      const id = req.params;
      const data = req.body;
      const query = { _id: new ObjectId(id) };
      const updateDoc = {
        $set: {
          jobBanner: data.jobBanner,
          companyName: data.companyName,
          companyLogo: data.companyLogo,
          jobTitle: data.jobTitle,
          loggedInUser: data.loggedInUser,
          jobCategory: data.jobCategory,
          salaryRange: data.salaryRange,
          jobDescription: data.jobDescription,
          jobPostingDate: data.jobPostingDate,
          applicationDeadline: data.applicationDeadline,
          vacancy: data.vacancy,
          jobApplicantsNumber: data.jobApplicantsNumber,
          userEmail: data.userEmail,
        },
      };
      const result = await jobCollection.updateOne(query, updateDoc);
      res.send(result);
    });

    //seekers apis
    app.get("/seekers", verifyToken, async (req, res) => {
      const email = req.query.email;
      if (!email) {
        return res.send([]);
      }
      const query = { seekerEmail: email };
      const appliedInfo = await seekersCollection.find(query).toArray();
      const jobIds = appliedInfo.map((info) => new ObjectId(info.jobId));
      const jobInfo = await jobCollection
        .find({ _id: { $in: jobIds } })
        .toArray();

      const combinedData = appliedInfo.map((info) => ({
        ...info,
        jobInfo: jobInfo.find((job) => job._id.toString() === info.jobId),
      }));

      res.send(combinedData);
    });

    app.post("/seekers", async (req, res) => {
      const data = req.body;
      const alreadyApplied = await seekersCollection.findOne({
        jobId: data.jobId,
        seekerEmail: data.seekerEmail,
      });
      if (alreadyApplied) {
        res.send({ message: "Already applied for this job." });
      } else {
        const result = await seekersCollection.insertOne(data);
        await jobCollection.updateOne(
          { _id: new ObjectId(data.jobId) },
          { $inc: { jobApplicantsNumber: 1 } }
        );
        res.send(result);
      }
    });

    // Send a ping to confirm a successful connection
    // await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("job-seeker is running");
});

app.listen(port, () => {
  console.log(`job seeker server is running on port: ${port}`);
});
