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
    const parcelsCollection = db.collection("parcels");
    const paymentCollection = db.collection("payments");
    // parcel api
    app.get("/parcels", verifyFBToken, async (req, res) => {
      const query = {};
      const { email } = req.query;
      if (email) {
        query.senderEmail = email;
        if (email !== req.decoded_email) {
          return res.status(403).send({ message: "forbidden access" });
        }
      }
      const options = { sort: { createdAt: -1 } };
      const cursor = parcelsCollection.find(query, options);
      const result = await cursor.toArray();
      res.send(result);
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
    app.patch("/payment-success",verifyFBToken,  async (req, res) => {
      const sessionId = req.query.session_id;
      const session = await stripe.checkout.sessions.retrieve(sessionId);
      if (session.customer_email !== req.decoded_email) {
        return res.status(403).send({ message: "forbidden access" });
      }

      const transactionId = session.payment_intent;
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

        // Get parcel info from parcels collection
        const parcel = await parcelsCollection.findOne({
          _id: new ObjectId(parcelId),
        });
        if (!parcel) {
          return res.status(404).send({ error: "Parcel not found" });
        }

        // Update parcel with payment status and tracking ID
        const trackingId = generateTrackingId();
        await parcelsCollection.updateOne(
          { _id: new ObjectId(parcelId) },
          { $set: { paymentStatus: "paid", trackingId } }
        );

        // Create payment object using parcel receiver info
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

        const resultPayment = await paymentCollection.insertOne(payment);

        return res.send({
          success: true,
          transactionId,
          trackingId,
          paymentInfo: resultPayment,
        });
      }

      res.send({ success: false });
    });

    // payment API
    app.get("/payments", verifyFBToken, async (req, res) => {
      const email = req.query.email;
      const query = {};

      if (email) {
        query.customer_email = email;
        // check email
        if (email !== req.decoded_email) {
          return res.status(403).send({ message: "forbidden access" });
        }
      }
      const cursor = paymentCollection.find(query).sort({ paidAt: -1 });
      const result = await cursor.toArray();
      res.send(result);
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
