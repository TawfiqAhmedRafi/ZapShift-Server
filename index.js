require("dotenv").config();
const express = require("express");
const cors = require("cors");
const app = express();
const stripe = require("stripe")(process.env.STRIPE_SECRET);
const crypto = require("crypto");
const admin = require("firebase-admin");

const serviceAccount = require("./zapshift-firebase-adminsdk.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

function generateTrackingId() {
  const prefix = "PRCL";
  const date = new Date().toISOString().slice(0, 10).replace(/-/g, "");
  const random = crypto.randomBytes(3).toString("hex").toUpperCase();

  return `${prefix}-${date}-${random}`;
}

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const port = process.env.PORT || 3000;

// middleware
app.use(express.json());
app.use(cors());

const verifyFBToken = async (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).send({ message: "Unauthorized access" });
  }
  try {
    const idToken = token.split(" ")[1];
    const decoded = await admin.auth().verifyIdToken(idToken);

    req.decoded_email = decoded.email;
    next();
  } catch (err) {
    return res.status(401).send({ message: "Unauthorized access" });
  }
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.eemz9pt.mongodb.net/?appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    const db = client.db("zap_shift_db");
    const userCollection = db.collection("users");
    const parcelsCollection = db.collection("parcels");
    const paymentCollection = db.collection("payments");
    const ridersCollection = db.collection("riders");

    //middleWare with database access
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await userCollection.findOne(query);
      if (!user || user.role !== "admin") {
        return res.status(403).send({ message: "Forbidden Access" });
      }
      next();
    };

    // user api
    app.get("/users", verifyFBToken, async (req, res) => {
      try {
        const { page = 1, limit = 10, search = "" } = req.query;

        // Convert page and limit to numbers
        const pageNumber = parseInt(page);
        const limitNumber = parseInt(limit);

        // Create search filter
        const searchFilter = search
          ? { displayName: { $regex: search, $options: "i" } } // case-insensitive search by displayName
          : {};

        // Count total matching documents
        const totalUsers = await userCollection.countDocuments(searchFilter);

        // Fetch users with pagination
        const users = await userCollection
          .find(searchFilter)
          .skip((pageNumber - 1) * limitNumber)
          .limit(limitNumber)
          .toArray();

        res.send({
          page: pageNumber,
          limit: limitNumber,
          totalUsers,
          totalPages: Math.ceil(totalUsers / limitNumber),
          users,
        });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Failed to fetch users" });
      }
    });

    app.get("/users/:email/role", async (req, res) => {
      const email = req.params.email;
      const query = { email };
      const user = await userCollection.findOne(query);
      res.send({ role: user?.role || "user" });
    });

    app.patch(
      "/users/:id/role",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const roleInfo = req.body;
        const query = { _id: new ObjectId(id) };
        const updatedDoc = {
          $set: {
            role: roleInfo.role,
          },
        };
        const result = await userCollection.updateOne(query, updatedDoc);
        res.send(result);
      }
    );

    app.post("/users", async (req, res) => {
      const user = req.body;
      user.role = "user";
      user.createdAt = new Date();
      const email = user.email;
      const userExist = await userCollection.findOne({ email });
      if (userExist) {
        return res.send({ message: "user exists" });
      }

      const result = await userCollection.insertOne(user);
      res.send(result);
    });

    app.delete("/users/:id", verifyFBToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await userCollection.deleteOne(query);
      res.send(result);
    });

    // rider api
    app.post("/riders", async (req, res) => {
      const rider = req.body;
      rider.status = "pending";
      rider.createdAt = new Date();

      const result = await ridersCollection.insertOne(rider);
      res.send(result);
    });

    app.get("/riders", async (req, res) => {
      try {
        const { status, district, workStatus } = req.query;
        const query = {};

        if (status) {
          query.status = status;
        }
        if (district) query.district = district;
        if (workStatus) query.workStatus = workStatus;

        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const sortOrder = req.query.sortOrder === "asc" ? 1 : -1;

        const cursor = ridersCollection
          .find(query)
          .sort({ createdAt: sortOrder })
          .skip(skip)
          .limit(limit);

        const result = await cursor.toArray();
        const total = await ridersCollection.countDocuments(query); // total items

        res.send({
          data: result,
          page,
          limit,
          totalPages: Math.ceil(total / limit),
          totalItems: total,
        });
      } catch (err) {
        console.error(err);
        res.status(500).send({ error: "Failed to fetch riders" });
      }
    });

    app.get("/riders/:id", verifyFBToken, verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;

        const rider = await ridersCollection.findOne({ _id: new ObjectId(id) });

        if (!rider) {
          return res.status(404).send({ message: "Rider not found" });
        }

        res.send(rider);
      } catch (error) {
        res.status(500).send({ message: "Error fetching rider", error });
      }
    });

    app.patch("/riders/:id", verifyFBToken, verifyAdmin, async (req, res) => {
      const status = req.body.status;
      const id = req.params.id;
      const email = req.body.email;

      const query = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          status: status,
          workStatus: "available",
        },
      };

      // Update the rider's status first
      const result = await ridersCollection.updateOne(query, updatedDoc);

      // Fetch the user to check role
      const user = await userCollection.findOne({ email });

      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }

      // Update role only if user is not admin
      if (user.role !== "admin") {
        if (status === "approved") {
          await userCollection.updateOne(
            { email },
            { $set: { role: "rider" } }
          );
        } else if (status === "rejected") {
          await userCollection.updateOne({ email }, { $set: { role: "user" } });
        }
      }

      res.send(result);
    });

    app.delete("/riders/:id", verifyFBToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await ridersCollection.deleteOne(query);
      res.send(result);
    });

    // parcel api
    app.get("/parcels", verifyFBToken, async (req, res) => {
      const { email, deliveryStatus } = req.query;
      const page = parseInt(req.query.page) || 1; // default page 1
      const limit = 10; // fixed limit
      const skip = (page - 1) * limit;

      const query = {};

      if (email) {
        query.senderEmail = email;
        if (email !== req.decoded_email) {
          return res.status(403).send({ message: "forbidden access" });
        }
      }

      if (deliveryStatus) {
        query.deliveryStatus = deliveryStatus;
      }

      const cursor = parcelsCollection
        .find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit);

      const result = await cursor.toArray();
      const total = await parcelsCollection.countDocuments(query);

      res.send({
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        data: result,
      });
    });

    app.get("/parcels/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await parcelsCollection.findOne(query);
      res.send(result);
    });
    app.post("/parcels", async (req, res) => {
      const parcel = req.body;
      parcel.createdAt = new Date();
      const result = await parcelsCollection.insertOne(parcel);
      res.send(result);
    });

    app.patch("/parcels/:id", async (req, res) => {
      const { riderId, riderName, riderEmail, riderPhone } = req.body;
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const updatedDoc = {
        $set: {
          deliveryStatus: "driver-assigned",
          riderId: riderId,
          riderName: riderName,
          riderPhone: riderPhone,
          riderEmail: riderEmail,
        },
      };

      const result = await parcelsCollection.updateOne(query, updatedDoc);
      // update rider
      const riderQuery = { _id: new ObjectId(riderId) };
      const riderUpdatedDoc = {
        $set: {
          workStatus: "in_delivery",
        },
      };
      const riderResult = await ridersCollection.updateOne(
        riderQuery,
        riderUpdatedDoc
      );
      res.send(riderResult);
    });

    app.delete("/parcels/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await parcelsCollection.deleteOne(query);
      res.send(result);
    });

    // new payment method
    app.post("/payment-checkout-session", async (req, res) => {
      const paymentInfo = req.body;
      const amount = parseInt(paymentInfo.cost) * 100;
      const session = await stripe.checkout.sessions.create({
        line_items: [
          {
            price_data: {
              currency: "USD",
              unit_amount: amount,
              product_data: {
                name: `Please pay for ${paymentInfo.parcelName}`,
              },
            },
            quantity: 1,
          },
        ],
        mode: "payment",
        metadata: {
          parcelId: paymentInfo.parcelId,
          parcelName: paymentInfo.parcelName,
        },
        customer_email: paymentInfo.senderEmail,
        success_url: `${process.env.SITE_DOMAIN}/dashboard/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${process.env.SITE_DOMAIN}/dashboard/payment-cancelled`,
      });
      res.send({ url: session.url });
    });

    //
    app.patch("/payment-success", verifyFBToken, async (req, res) => {
      const sessionId = req.query.session_id;
      const session = await stripe.checkout.sessions.retrieve(sessionId);

      if (session.customer_email !== req.decoded_email) {
        return res.status(403).send({ message: "forbidden access" });
      }

      const transactionId = session.payment_intent;

      // Check if payment already exists
      const paymentExist = await paymentCollection.findOne({ transactionId });
      if (paymentExist) {
        return res.send({
          message: "already exists",
          transactionId,
          trackingId: paymentExist.trackingId,
        });
      }

      if (session.payment_status === "paid") {
        const parcelId = session.metadata.parcelId;

        // Get parcel info
        const parcel = await parcelsCollection.findOne({
          _id: new ObjectId(parcelId),
        });
        if (!parcel) {
          return res.status(404).send({ error: "Parcel not found" });
        }

        // Generate trackingId only once
        const trackingId = generateTrackingId();

        // Update parcel
        await parcelsCollection.updateOne(
          { _id: new ObjectId(parcelId) },
          {
            $set: {
              paymentStatus: "paid",
              deliveryStatus: "pending-pickup",
              trackingId,
            },
          }
        );

        // Prepare payment object
        const payment = {
          amount: session.amount_total / 100,
          currency: session.currency,
          customer_email: session.customer_email,
          parcelId: parcelId,
          parcelName: session.metadata.parcelName,
          transactionId,
          paymentStatus: session.payment_status,
          paidAt: new Date(),
          trackingId,
          receiverName: parcel.receiverName,
          receiverAddress: parcel.receiverAddress,
          receiverRegion: parcel.receiverRegion,
          receiverDistrict: parcel.receiverDistrict,
          receiverPhone: parcel.receiverPhoneNumber,
        };

        // Upsert payment to avoid duplicates
        const resultPayment = await paymentCollection.updateOne(
          { transactionId }, // filter
          { $setOnInsert: payment }, // only insert if not exists
          { upsert: true } // ensures single document
        );

        return res.send({
          success: true,
          transactionId,
          trackingId,
          paymentInfo: resultPayment,
        });
      }

      res.send({ success: false });
    });

    app.get("/payments", verifyFBToken, async (req, res) => {
      const email = req.query.email;

      const page = parseInt(req.query.page) || 1; // default page = 1
      const limit = 10; // fixed limit
      const skip = (page - 1) * limit;

      const query = {};

      if (email) {
        query.customer_email = email;
        // check email
        if (email !== req.decoded_email) {
          return res.status(403).send({ message: "forbidden access" });
        }
      }

      const cursor = paymentCollection
        .find(query)
        .sort({ paidAt: -1 }) // descending
        .skip(skip)
        .limit(limit);

      const result = await cursor.toArray();

      // Optional: total count (useful for frontend pagination)
      const total = await paymentCollection.countDocuments(query);

      res.send({
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        data: result,
      });
    });

    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("Zap is shifting shifting");
});

app.listen(port, () => {
  console.log(`Zapshift app listening on port ${port}`);
});
