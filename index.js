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
    const trackingsCollection = db.collection("trackings");

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
    const verifyRider = async (req, res, next) => {
      const email = req.decoded_email;
      const query = { email };
      const user = await userCollection.findOne(query);
      if (!user || user.role !== "rider") {
        return res.status(403).send({ message: "Forbidden Access" });
      }
      next();
    };

    const logTracking = async (trackingId, status) => {
      const update = {
        $setOnInsert: {
          trackingId,
          status,
          details: status.split("-").join(" "),
          createdAt: new Date(),
        },
      };
      const options = { upsert: true };
      return await trackingsCollection.updateOne(
        { trackingId, status },
        update,
        options
      );
    };

    // tracking api
    app.get("/trackings/:trackingId/logs", async (req, res) => {
      const trackingId = req.params.trackingId;
      const query = { trackingId };
      const result = await trackingsCollection.find(query).toArray();
      res.send(result);
    });

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

    // rider dashboard  api
   // Rider Dashboard Stats
app.get("/rider/dashboard/stats", verifyFBToken, verifyRider, async (req, res) => {
  try {
    const email = req.query.email || req.decoded_email;

    const rider = await ridersCollection.findOne({ Email: email  });
    if (!rider)
      return res.status(404).send({ message: "Rider not found" });

    const riderId = rider._id.toString();

    const totalDeliveries = await parcelsCollection.countDocuments({ riderId });
    const delivered = await parcelsCollection.countDocuments({
      riderId,
      deliveryStatus: "parcel-delivered",
    });
    const pending = await parcelsCollection.countDocuments({
      riderId,
      deliveryStatus: { $nin: ["parcel-delivered"] },
    });

    res.send({
      riderName: rider.name,
      totalDeliveries,
      delivered,
      pending,
      workStatus: rider.workStatus,
      status: rider.status,
    });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch rider stats" });
  }
});



// Rider Dashboard Completed Parcels
app.get("/rider/dashboard/completed", verifyFBToken, verifyRider, async (req, res) => {
  try {
    const email = req.query.email || req.decoded_email;

    const rider = await ridersCollection.findOne({ Email: email  });
    if (!rider)
      return res.status(404).send({ message: "Rider not found" });

    const riderId = rider._id.toString();

    const parcels = await parcelsCollection
      .find({ riderId, deliveryStatus: "parcel-delivered" })
      .sort({ createdAt: -1 })
      .toArray();

    res.send(parcels);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch completed deliveries" });
  }
});

// Rider Dashboard Performance
app.get("/rider/dashboard/performance", verifyFBToken, verifyRider, async (req, res) => {
  try {
    const email = req.query.email || req.decoded_email;

    const rider = await ridersCollection.findOne({ Email: email  });
    if (!rider)
      return res.status(404).send({ message: "Rider not found" });

    const riderId = rider._id.toString();

    const pipeline = [
      { $match: { riderId, deliveryStatus: "parcel-delivered" } },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
          delivered: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 } },
      { $project: { date: "$_id", delivered: 1, _id: 0 } },
    ];

    const performance = await parcelsCollection.aggregate(pipeline).toArray();

    res.send(performance);
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to fetch performance data" });
  }
});


    // rider api
    app.post("/riders", verifyFBToken, async (req, res) => {
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

    app.patch("/riders/work-status", verifyFBToken, verifyRider, async (req, res) => {
  try {
    const { email, newWorkStatus } = req.body;

    if (!email || !newWorkStatus) {
      return res.status(400).send({ message: "Email and newWorkStatus are required" });
    }

    // Find the rider
    const rider = await ridersCollection.findOne({ Email: email });
    if (!rider) {
      return res.status(404).send({ message: "Rider not found" });
    }

    // Prevent manual change if rider is currently in delivery
    if (rider.workStatus === "in_delivery") {
      return res.status(403).send({
        message: "Cannot change work status while in delivery"
      });
    }

    // Update the workStatus
    const updated = await ridersCollection.updateOne(
      { Email: email },
      { $set: { workStatus: newWorkStatus } }
    );

    res.send({ success: true, updatedCount: updated.modifiedCount, newWorkStatus });
  } catch (err) {
    console.error(err);
    res.status(500).send({ message: "Failed to update work status", error: err.message });
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
          workStatus: status === "rejected" ? "" : "available",
        },
      };

      try {
        const result = await ridersCollection.updateOne(query, updatedDoc);

        const user = await userCollection.findOne({ email });

        if (user) {
          if (user.role !== "admin") {
            if (status === "approved") {
              await userCollection.updateOne(
                { email },
                { $set: { role: "rider" } }
              );
            } else if (status === "rejected") {
              await userCollection.updateOne(
                { email },
                { $set: { role: "user" } }
              );
            }
          }
        }

        res.send(result);
      } catch (err) {
        console.error(err);
        res.status(500).send({
          message: "Something went wrong while updating rider",
          error: err.message,
        });
      }
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
    app.get("/parcels/rider", verifyFBToken, verifyRider, async (req, res) => {
      const { riderEmail, deliveryStatus } = req.query;
      const query = {};

      if (riderEmail) {
        query.riderEmail = riderEmail;
      }

      if (deliveryStatus !== "parcel-delivered") {
        query.deliveryStatus = { $nin: ["parcel-delivered"] };
      } else {
        query.deliveryStatus = deliveryStatus;
      }

      const result = await parcelsCollection
        .find(query)
        .sort({ _id: -1 })
        .toArray();

      res.send(result);
    });

    app.get("/parcels/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await parcelsCollection.findOne(query);
      res.send(result);
    });

    app.patch(
      "/parcels/:id/status",
      verifyFBToken,
      verifyRider,
      async (req, res) => {
        try {
          const { deliveryStatus, workStatus, trackingId } = req.body;
          const parcelId = req.params.id;

          //  Find the parcel
          const parcel = await parcelsCollection.findOne({
            _id: new ObjectId(parcelId),
          });
          if (!parcel)
            return res.status(404).send({ message: "Parcel not found" });

          let riderId = parcel.riderId;

          //  Handle rejection
          let clearRider = {};
          if (deliveryStatus === "parcel-paid" && riderId) {
            await ridersCollection.updateOne(
              { _id: new ObjectId(riderId) },
              { $set: { workStatus: "available" } }
            );

            riderId = ""; // clear local variable
            clearRider = {
              riderId: "",
              riderEmail: "",
              riderName: "",
              riderPhone: "",
            };
          }

          //  Update rider workStatus for normal flow
          if (deliveryStatus !== "parcel-paid" && riderId) {
            await ridersCollection.updateOne(
              { _id: new ObjectId(riderId) },
              { $set: { workStatus } }
            );
          }

          //  Update parcel
          const updatedParcel = {
            $set: {
              deliveryStatus,
              ...clearRider,
            },
          };

          const result = await parcelsCollection.updateOne(
            { _id: new ObjectId(parcelId) },
            updatedParcel
          );
          logTracking(trackingId, deliveryStatus);
          res.send(result);
        } catch (err) {
          console.error(err);
          res.status(500).send({ message: "Internal server error" });
        }
      }
    );

    app.post("/parcels", async (req, res) => {
      const parcel = req.body;
      const trackingId = generateTrackingId();
      parcel.createdAt = new Date();
      parcel.trackingId = trackingId;
      logTracking(trackingId, "parcel-created");
      const result = await parcelsCollection.insertOne(parcel);
      res.send(result);
    });

    app.patch("/parcels/:id", async (req, res) => {
      const { riderId, riderName, riderEmail, riderPhone, trackingId } =
        req.body;
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
      // log tracking
      logTracking(trackingId, "driver-assigned");
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
          trackingId: paymentInfo.trackingId,
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

        // trackingId created created during parcel creation
        const trackingId = session.metadata.trackingId; //
        await parcelsCollection.updateOne(
          { _id: parcel._id },
          {
            $set: {
              paymentStatus: "paid",
              deliveryStatus: "parcel-paid",
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

        // Log tracking only if it doesn't already exist
        const existingLog = await trackingsCollection.findOne({
          trackingId,
          status: "parcel-paid",
        });
        if (!existingLog) {
          await logTracking(trackingId, "parcel-paid");
        }

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

    // dashboard API

    app.get(
      "/dashboard/stats",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const totalParcels = await parcelsCollection.countDocuments();
          const deliveredParcels = await parcelsCollection.countDocuments({
            deliveryStatus: "parcel-delivered",
          });
          const pendingParcels = await parcelsCollection.countDocuments({
            deliveryStatus: { $nin: ["parcel-delivered"] },
          });

          const totalRevenueAgg = await paymentCollection
            .aggregate([
              { $match: { amount: { $exists: true, $type: "number" } } },
              { $group: { _id: null, total: { $sum: "$amount" } } },
            ])
            .toArray();
          const totalRevenue = totalRevenueAgg[0]?.total || 0;

          const totalUsers = await userCollection.countDocuments();
          const totalRiders = await ridersCollection.countDocuments();

          res.send({
            totalParcels,
            deliveredParcels,
            pendingParcels,
            totalRevenue,
            totalUsers,
            totalRiders,
          });
        } catch (err) {
          console.error(err);
          res.status(500).send({ message: "Failed to fetch dashboard stats" });
        }
      }
    );

    app.get(
      "/dashboard/delivery-status",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const pipeline = [
            { $match: { deliveryStatus: { $exists: true, $ne: null } } },
            { $group: { _id: "$deliveryStatus", count: { $sum: 1 } } },
            { $project: { status: "$_id", count: 1, _id: 0 } },
          ];
          const result = await parcelsCollection.aggregate(pipeline).toArray();
          res.send(result);
        } catch (err) {
          console.error(err);
          res
            .status(500)
            .send({ message: "Failed to fetch delivery status data" });
        }
      }
    );

    app.get(
      "/dashboard/revenue",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const { period = "monthly" } = req.query; // default monthly

          let groupId;
          if (period === "weekly") {
            groupId = {
              $dateToString: { format: "%Y-%U", date: "$paidAt" }, //
            };
          } else {
            groupId = {
              $dateToString: { format: "%Y-%m", date: "$paidAt" },
            };
          }

          const pipeline = [
            { $match: { paidAt: { $exists: true, $type: "date" } } },
            {
              $group: {
                _id: groupId,
                totalRevenue: { $sum: "$amount" },
              },
            },
            { $sort: { _id: 1 } },
            { $project: { period: "$_id", totalRevenue: 1, _id: 0 } },
          ];

          const result = await paymentCollection.aggregate(pipeline).toArray();
          res.send(result);
        } catch (err) {
          console.error(err);
          res.status(500).send({ message: "Failed to fetch revenue" });
        }
      }
    );

    app.get(
      "/dashboard/rider-performance",
      verifyFBToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const pipeline = [
            { $match: { riderId: { $exists: true, $ne: "" } } },
            {
              $group: {
                _id: "$riderId",
                deliveries: { $sum: 1 },
              },
            },
            {
              $lookup: {
                from: "riders",
                let: { riderIdStr: "$_id" },
                pipeline: [
                  {
                    $match: {
                      $expr: { $eq: ["$_id", { $toObjectId: "$$riderIdStr" }] },
                    },
                  },
                ],
                as: "riderInfo",
              },
            },
            { $unwind: "$riderInfo" },
            {
              $project: {
                _id: 0,
                riderId: "$_id",
                riderName: "$riderInfo.name",
                region: "$riderInfo.region",
                district: "$riderInfo.district",
                deliveries: 1,
                status: "$riderInfo.status",
                workStatus: "$riderInfo.workStatus",
              },
            },
            { $sort: { deliveries: -1 } },
          ];

          const result = await parcelsCollection.aggregate(pipeline).toArray();
          res.send(result);
        } catch (err) {
          console.error(err);
          res
            .status(500)
            .send({ message: "Failed to fetch rider performance" });
        }
      }
    );

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
