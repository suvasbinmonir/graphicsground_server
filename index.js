const express = require("express");
const app = express();
const AWS = require("aws-sdk");
const multer = require("multer");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();
const bodyParser = require("body-parser");

const PORT = process.env.PORT || 5000;
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const ImageKit = require("imagekit");
const Fuse = require("fuse.js");
const stripe = require("stripe")(process.env.STRIPE_SECRECT_KEY);
const imagekit = new ImageKit({
  publicKey: process.env.IMAGEKIT_PUBLIC_KEY,
  privateKey: process.env.IMAGEKIT_PRIVATE_KEY,
  urlEndpoint: process.env.IMAGEKIT_URL_ENDPOINT,
});
const corsOptions = {
  origin: "https://graphicsground.com/", // or '*' for all origins (not recommended for production)
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
};

app.use(cors(corsOptions));
// app.use(cors());
app.use(express.json({ limit: "50mb" })); // Adjust as needed
app.use(express.urlencoded({ limit: "50mb", extended: true }));
app.use(bodyParser.json());

const client = new MongoClient(process.env.MONGODB_URI);

async function run() {
  try {
    await client.connect();
    const usersCollection = client.db("graphics-ground").collection("users");
    const reviewCollection = client.db("graphics-ground").collection("review");
    const logosCollection = client.db("graphics-ground").collection("logos");
    const fileCollection = client.db("graphics-ground").collection("files");
    const caseCollection = client.db("graphics-ground").collection("casestudy");
    const requirementCollection = client
      .db("graphics-ground")
      .collection("requirement");
    const categoryCollection = client
      .db("graphics-ground")
      .collection("category");
    const paymentCollection = client
      .db("graphics-ground")
      .collection("payments");
    const caseStudiesCollection = client
      .db("graphics-ground")
      .collection("case-studies");
    const packageCollection = client
      .db("graphics-ground")
      .collection("package");

    // const indexes = await logosCollection.indexes();
    //  (indexes);

    await logosCollection
      .dropIndex("title_text_tag_text_category_text")
      .catch((err) => {});
    await logosCollection.createIndex(
      { title: "text", tag: "text", description: "text" },
      { weights: { description: 1, tag: 1, title: 1 } }
    );

    // Search endpoint
    app.get("/api/search", async (req, res) => {
      const query = req.query.query;

      if (!query) {
        return res.status(400).json({ message: "Search query is required." });
      }

      try {
        const initialResults = await logosCollection
          .find(
            { $text: { $search: query } },
            { score: { $meta: "textScore" } }
          )
          .sort({ score: { $meta: "textScore" } })
          .toArray();
        const uniqueInitialResults = Array.from(
          new Map(initialResults.map((logo) => [logo._id, logo])).values()
        );
        res.json(uniqueInitialResults);
        const queryParts = query.split(" ");
        let searchQueries = [query];
        if (queryParts.length > 1) {
          const combinations = [
            queryParts[0] + " " + queryParts[1],
            queryParts[1] + " " + queryParts[0],
          ];
          searchQueries.push(...combinations);
        }
        const charCombinations = query.split("").map((char) => `${char} logo`);
        searchQueries.push(...charCombinations);

        searchQueries = [...new Set(searchQueries)];
        for (let searchTerm of searchQueries) {
          const queryResult = await logosCollection
            .find(
              { $text: { $search: searchTerm } },
              { score: { $meta: "textScore" } }
            )
            .sort({ score: { $meta: "textScore" } })
            .toArray();
        }
      } catch (error) {
        console.error("Error during search:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // DigitalOcean Spaces setup
    const spacesEndpoint = new AWS.Endpoint("nyc3.digitaloceanspaces.com");
    const s3 = new AWS.S3({
      endpoint: spacesEndpoint,
      accessKeyId: process.env.DO_ACCESS_KEY,
      secretAccessKey: process.env.DO_SECRET_KEY,
    });
    const storage = multer.memoryStorage();
    const upload = multer({ storage: storage });
    //generate custom id
    const generateCustomId = async () => {
      const randomNumber = Math.floor(10000 + Math.random() * 90000);
      const customId = `gg${randomNumber}`;
      const existingEntry = await fileCollection.findOne({ _id: customId });
      return existingEntry ? generateCustomId() : customId;
    };

    app.post("/api/jwt", async (req, res) => {
      const user = req.body;
      const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
        expiresIn: "1h",
      });
      res.send({ token });
    });
    const verifyToken = (req, res, next) => {
      if (!req.headers.authorization) {
        return res.status(401).send({ message: "unauthorized access" });
      }
      const token = req.headers.authorization.split(" ")[1];
      jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
          return res.status(401).send({ message: "unauthorized access" });
        }
        req.decoded = decoded;
        next();
      });
    };
    const verifyAdmin = async (req, res, next) => {
      const email = req.decoded.email;
      const query = { email: email };
      const user = await usersCollection.findOne(query);
      if (!user) {
        return res.status(404).send({ message: "User not found" });
      }
      const isAdmin = user.role === "admin";
      if (!isAdmin) {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };

    app.post("/casestudy", upload.array("images", 100), async (req, res) => {
      try {
        const { fields, category, name } = req.body;
        // console.log(fields, category, "hi");
        const images = req.files;
        // console.log(images, "consoling images");

        if (!fields || !category) {
          return res.status(400).json({
            success: false,
            message: "Fields and category are required.",
          });
        }

        // Parse the fields back into objects
        const parsedFields = fields.map((field) => JSON.parse(field));

        if (!images || images.length === 0) {
          return res.status(400).json({
            success: false,
            message: "At least one image is required.",
          });
        }

        // Prepare image URLs for upload, using the customId from the corresponding field
        const imageUrls = await Promise.all(
          images.map(async (file, index) => {
            // console.log(file, "this file");

            // Match images to their respective fields using the index
            const matchingField = parsedFields[index]; // Directly use index to match the corresponding field
            // console.log(matchingField, "field mc");

            const customId =
              matchingField && matchingField.customId
                ? matchingField.customId
                : `gg-${Date.now()}-${index + 1}`; // Default to a unique ID if not provided

            const params = {
              Bucket: "graphics-ground-llc",
              Key: `${customId}-${file.originalname}`,
              Body: file.buffer,
              ContentType: file.mimetype,
              ACL: "public-read",
            };

            try {
              const uploadResult = await s3.upload(params).promise();
              return { customId, url: uploadResult.Location };
            } catch (uploadError) {
              console.error("Image upload error:", uploadError);
              return null;
            }
          })
        );

        // console.log(imageUrls, "consoling image urls");
        const validImageUrls = imageUrls.filter((img) => img !== null);

        // Combine the fields with the uploaded images
        const caseStudyData = parsedFields.map((field) => {
          if (field.type === "text") {
            return {
              type: "text",
              customId: field.customId,
              value: field.value,
              bold: field.bold,
              italic: field.italic,
              size: field.size,
              alignment: field.alignment,
              color: field.color,
            };
          } else if (field.type === "image") {
            // Match the field's customId with the uploaded image's customId
            const matchingImage = validImageUrls.find(
              (img) => img.customId === field.customId
            );
            return {
              type: "image",
              customId: field.customId,
              url: matchingImage ? matchingImage.url : null, // Attach the URL if found
            };
          }
        });

        // console.log(caseStudyData, "Consoling caseStudyData");

        // Save the case study data to the database
        const result = await caseCollection.insertOne({
          name,
          category,
          fields: caseStudyData,
        });
        // console.log(result, "Consoling result.....");

        res.status(200).json({ success: true, data: caseStudyData });
      } catch (error) {
        console.error("Server error:", error);
        res.status(500).json({
          success: false,
          message: "Server error",
          error: error.message,
        });
      }
    });
    app.get("/api/casestudy", async (req, res) => {
      const result = await caseCollection.find().toArray();
      res.send(result);
    });
    app.post(
      "/requirement",
      upload.fields([
        { name: "images", maxCount: 10 },
        { name: "zipFiles", maxCount: 10 },
      ]),
      async (req, res) => {
        try {
          const {
            name,
            slogan,
            color,
            description,
            ideas,
            requireCustomId,
            title,
          } = req.body;

          // Store images in DigitalOcean Spaces
          const imageUrls = [];
          if (req.files["images"]) {
            for (const file of req.files["images"]) {
              const fileName = `images/${Date.now()}-${file.originalname}`;
              const params = {
                Bucket: "graphics-ground-llc",
                Key: fileName,
                Body: file.buffer,
                ACL: "public-read",
              };

              const uploadResult = await s3.upload(params).promise();
              imageUrls.push(uploadResult.Location);
            }
          }

          // Store zip files in DigitalOcean Spaces
          const zipFileUrls = [];
          if (req.files["zipFiles"]) {
            for (const file of req.files["zipFiles"]) {
              const fileName = `zipFiles/${Date.now()}-${file.originalname}`;
              const params = {
                Bucket: "graphics-ground-llc",
                Key: fileName,
                Body: file.buffer,
                ACL: "public-read",
              };

              const uploadResult = await s3.upload(params).promise();
              zipFileUrls.push(uploadResult.Location);
            }
          }
          // Prepare data to store in MongoDB
          const requirementData = {
            name,
            requireCustomId,
            slogan,
            title,
            color,
            description,
            ideas,
            imageUrls, // URLs for uploaded images
            zipFileUrls, // URLs for uploaded zip files
            createdAt: new Date(),
          };

          // Insert into MongoDB
          const result = await requirementCollection.insertOne(requirementData);

          res.status(201).json({
            message: "Requirement submitted successfully",
            data: requirementData,
            insertedId: result.insertedId,
          });
        } catch (error) {
          console.error("Error submitting requirement:", error);
          res.status(500).json({ error: "Internal Server Error" });
        }
      }
    );

    app.get("/api/requirement", verifyToken, verifyAdmin, async (req, res) => {
      const result = await requirementCollection.find().toArray();
      res.send(result);
    });
    app.get("/api/getCustomIds", async (req, res) => {
      try {
        const documents = await requirementCollection
          .find({}, { projection: { requireCustomId: 1 } })
          .toArray();
        const customIds = documents.map((doc) => doc.requireCustomId); // Extract the 'requireCustomId' from the response
        res.json(customIds); // Send the list of custom IDs as a response
      } catch (err) {
        console.error(err);
        res.status(500).send("Server error");
      }
    });
    app.post(
      "/api/upload",
      upload.fields([{ name: "images" }, { name: "zipFile" }]),
      async (req, res) => {
        try {
          const {
            title,
            price,
            tag,
            selectedCategories,
            descriptionTitle,
            descriptionPoint,
            descriptionConclusion,
          } = req.body;

          // Parse `selectedCategories` if it's a JSON string
          let parsedCategories;
          try {
            parsedCategories =
              typeof selectedCategories === "string"
                ? JSON.parse(selectedCategories)
                : selectedCategories;
          } catch (parseError) {
            return res
              .status(400)
              .json({ message: "Invalid format for selectedCategories" });
          }

          const images = req.files["images"];
          const zipFile = req.files["zipFile"]?.[0];

          if (!images || images.length === 0) {
            return res.status(400).json({ message: "No images uploaded." });
          }

          // Image upload to DigitalOcean Spaces
          const imageUploadPromises = images.map((image) => {
            const params = {
              Bucket: "graphics-ground-llc",
              Key: `images/${Date.now()}-${image.originalname}`,
              Body: image.buffer,
              ACL: "public-read",
            };
            return s3.upload(params).promise();
          });

          const imageUploads = await Promise.all(imageUploadPromises);

          // Zip file upload to DigitalOcean Spaces
          let zipUpload = null;
          if (zipFile) {
            const zipParams = {
              Bucket: "graphics-ground-llc",
              Key: `zips/${Date.now()}-${zipFile.originalname}`,
              Body: zipFile.buffer,
              ACL: "public-read",
            };
            zipUpload = await s3.upload(zipParams).promise();
          }

          const customId = await generateCustomId();
          const newEntry = {
            _id: customId,
            title,
            price,
            tag,
            selectedCategories: parsedCategories, // Save parsed categories
            descriptionTitle,
            descriptionPoint,
            descriptionConclusion,
            imageUrls: imageUploads.map((upload) => upload.Location),
            zipUrl: zipUpload ? zipUpload.Location : null,
          };

          // Insert into MongoDB
          await logosCollection.insertOne(newEntry);

          // Respond with success
          res.status(200).json({
            message: "Upload successful",
            data: newEntry,
          });
        } catch (error) {
          console.error(error);
          res.status(500).json({
            message: "Error uploading files",
            error: error.message,
          });
        }
      }
    );

    app.patch("/api/logos/:id", async (req, res) => {
      const productId = req.params.id;
      const { status, isFeatured } = req.body; // Accept both 'status' and 'isFeatured' from the frontend

      try {
        const updateFields = {};

        // Dynamically add fields to update
        if (status) updateFields.status = status;
        if (isFeatured) updateFields.isFeatured = isFeatured;

        if (Object.keys(updateFields).length === 0) {
          return res
            .status(400)
            .json({ message: "No valid fields provided for update." });
        }

        const result = await logosCollection.updateOne(
          { _id: productId },
          { $set: updateFields } // Dynamically set fields to update
        );

        if (result.modifiedCount > 0) {
          res.status(200).json({
            message: "Product updated successfully.",
            updatedFields: updateFields,
          });
        } else {
          res.status(404).json({ message: "Product not found." });
        }
      } catch (error) {
        console.error("Error updating product:", error);
        res.status(500).json({ message: "Failed to update product." });
      }
    });

    app.post("/api/review", async (req, res) => {
      const reviewData = req.body;

      try {
        // Fetch the last review document with a matching ID format
        const lastReview = await reviewCollection
          .find({ _id: { $regex: /^gg-r-/ } })
          .sort({ _id: -1 })
          .limit(1)
          .toArray();

        // Determine the new custom _id
        let newCustomId;
        if (lastReview.length > 0 && typeof lastReview[0]._id === "string") {
          const idParts = lastReview[0]._id.split("-"); // Split by dashes
          const lastIdNumber = parseInt(idParts[2], 10); // Extract the numeric part
          // console.log(lastIdNumber, "this is the last number");

          if (!isNaN(lastIdNumber)) {
            newCustomId = `gg-r-${lastIdNumber + 1}`; // Increment the numeric part
          } else {
            newCustomId = "gg-r-1001"; // Fallback for malformed ID
          }
        } else {
          newCustomId = "gg-r-1001"; // Initial custom ID if no records exist
        }

        // Assign the custom ID to the new review
        reviewData._id = newCustomId;

        // Insert the review into the database
        const result = await reviewCollection.insertOne(reviewData);
        res.status(201).json({
          success: true,
          message: "Review submitted successfully",
          data: result,
        });
      } catch (error) {
        console.error("Error inserting review:", error);
        res.status(500).json({
          success: false,
          message: "Failed to submit the review",
          error: error.message,
        });
      }
    });

    app.get("/api/review", async (req, res) => {
      const result = await reviewCollection.find().toArray();
      res.send(result);
    });
    app.post("/api/users", async (req, res) => {
      const user = req.body;

      // Check if a user with this email already exists
      const existingUser = await usersCollection.findOne({ email: user.email });
      if (existingUser) {
        return res.status(409).send({ message: "User already exists" });
      }

      const lastUser = await usersCollection
        .find({ _id: { $regex: /^gg-/ } })
        .sort({ _id: -1 })
        .limit(1)
        .toArray();

      let newCustomId;
      if (lastUser.length > 0 && typeof lastUser[0]._id === "string") {
        const lastIdNumber = parseInt(lastUser[0]._id.split("-")[1], 10);
        newCustomId = `gg-${lastIdNumber + 1}`;
      } else {
        newCustomId = "gg-1001";
      }

      user._id = newCustomId;

      const result = await usersCollection.insertOne(user);
      res.send(result);
    });
    app.delete("/api/users/:id", verifyToken, verifyAdmin, async (req, res) => {
      const id = req.params.id;
      const query = { _id: id };
      const result = await usersCollection.deleteOne(query);
      res.send(result);
    });
    app.get("/api/users/:role", async (req, res) => {
      try {
        // Fetch users where the 'role' field exists and is not empty
        const usersWithRole = await usersCollection
          .find({ role: { $exists: true, $ne: "" } })
          .toArray();
        res.status(200).json(usersWithRole);
      } catch (error) {
        console.error("Error fetching users with a role:", error);
        res.status(500).json({ message: "Server error" });
      }
    });
    app.get(
      "/api/users/admin/:email",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const email = req.params.email;

        if (email !== req.decoded.email) {
          return res.status(403).send({ message: "forbidden access" });
        }

        const query = { email: email };
        const user = await usersCollection.findOne(query);
        let admin = false;
        if (user) {
          admin = user?.role === "admin";
        }
        res.send({ admin });
      }
    );
    app.patch(
      "/api/users/admin/:id",
      verifyToken,
      verifyAdmin,
      async (req, res) => {
        const id = req.params.id;
        const filter = { _id: id };
        const updatedDoc = {
          $set: {
            role: "admin",
          },
        };
        const result = await usersCollection.updateOne(filter, updatedDoc);
        res.send(result);
      }
    );
    app.get("/api/users", verifyToken, verifyAdmin, async (req, res) => {
      const result = await usersCollection.find().toArray();
      res.send(result);
    });
    app.get("/api/users/:email", verifyToken, async (req, res) => {
      try {
        const email = req.params.email;
        const user = await usersCollection.findOne({ email: email });

        if (!user) {
          return res.status(404).json({ message: "User not found" });
        }

        res.send(user);
      } catch (error) {
        res.status(500).json({ error: "Internal Server Error" });
      }
    });
    app.delete("/api/logos/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: id };
      const result = await logosCollection.deleteOne(query);
      res.send(result);
    });
    app.get("/api/logos", async (req, res) => {
      const result = await logosCollection.find().toArray();
      res.send(result);
    });
    app.get("/api/package", async (req, res) => {
      const result = await packageCollection.find().toArray();
      res.send(result);
    });
    app.get("/api/case-studies", async (req, res) => {
      const result = await caseStudiesCollection.find().toArray();
      res.send(result);
    });
    app.get("/api/category", async (req, res) => {
      const result = await categoryCollection.find().toArray();
      res.send(result);
    });
    app.post("/api/create-payment-intent", async (req, res) => {
      try {
        const { price } = req.body;
        if (!price) {
          return res.status(400).send({ error: "Price is required" });
        }
        const priceis = Number(price);
        const amount = parseInt(priceis * 100);
        // console.log(amount, "amount inside the intent");

        const paymentIntent = await stripe.paymentIntents.create({
          amount: amount,
          currency: "usd",
          payment_method_types: ["card"],
        });
        res.send({
          clientSecret: paymentIntent.client_secret,
        });
      } catch (error) {
        console.error("Error creating payment intent:", error.message);
        res.status(500).send({ error: "Payment intent creation failed" });
      }
    });
    app.post("/api/payments", async (req, res) => {
      try {
        const payment = req.body;

        // Fetch the last payment to determine the new custom _id
        const lastPayment = await paymentCollection
          .find({ _id: { $regex: /^gg-/ } })
          .sort({ _id: -1 })
          .limit(1)
          .toArray();

        let newCustomId;
        if (lastPayment.length > 0 && typeof lastPayment[0]._id === "string") {
          const lastIdNumber = parseInt(lastPayment[0]._id.split("-")[1], 10);
          newCustomId = `gg-${lastIdNumber + 1}`;
        } else {
          newCustomId = "gg-1001";
        }

        const paymentData = {
          _id: newCustomId,
          email: payment.email,
          purchased: payment.purchased,
        };

        const existingPayment = await paymentCollection.findOne({
          email: payment.email,
        });

        if (existingPayment) {
          // If it exists, update the existing document by pushing new purchased item
          await paymentCollection.updateOne(
            { email: payment.email },
            { $push: { purchased: payment.purchased[0] } }
          );
          return res.send({ message: "Purchased item added successfully." });
        } else {
          // If it doesn't exist, insert the new payment document
          await paymentCollection.insertOne(paymentData);
          return res.send({ message: "Purchased item added successfully." });
        }
      } catch (error) {
        console.error("Error processing payment:", error);
        res.status(500).send({ error: "Failed to process payment." });
      }
    });

    app.get("/api/payments", async (req, res) => {
      const result = await paymentCollection.find().toArray();
      res.send(result);
    });
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // await client.close();
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.send("server is running");
});

app.listen(5000, "0.0.0.0", () => {
  console.log(`Server is running on port ${PORT}`);
});
