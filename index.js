const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const path = require("path");
const session = require("express-session");
const ejs = require("ejs");
const multer = require("multer");
const cookieParser = require("cookie-parser");
const { ObjectId } = require("mongodb");
const Stripe = require("stripe");
const cors = require("cors");

const http = require("http");
const stripe = Stripe(
  "sk_test_51O1qFMKiAN37OnJdKEWRj3a0oCjlxjs5K6pmCfREwnZPgRsqqrKIqKOIpD5iS0Kj96GDdVIXSDcaRJBtsN5tsjRH00nxbQlbD0"
);

const sharp = require("sharp");
const fs = require("fs");
const { v4: uuidv4 } = require("uuid");

const app = express();
const PORT = process.env.PORT || 3000;
app.use(
  session({
    secret: "game",
    resave: false,
    saveUninitialized: true,
    cookie: { expires: new Date(Date.now() + 24 * 60 * 60 * 1000) }, // expires in 1 day
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());

async function connectToDatabase() {
  console.log("done");
  try {
    console.log("here");
    await mongoose.connect("mongodb://127.0.0.1:27017/mydatabase", {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      connectTimeoutMS: 10000,
    });

    const db = mongoose.connection;

    db.on("error", console.error.bind(console, "MongoDB connection error:"));
    db.once("open", () => {
      console.log("Connected to MongoDB");
    });
  } catch (error) {
    console.error("Error connecting to MongoDB:", error);
    process.exit(1); // Exit the application with an error code
  }
}

// Call the function to initiate the connection
connectToDatabase();
const baloonSchema = new mongoose.Schema({
  name: { type: String, required: false },
  price: { type: String, required: false },
  color: { type: String, required: false },
  size: { type: String, required: false },
  quantity: { type: String, required: false },
  image: { type: String, required: false },
  type: { type: String, required: true },
  subId: { type: mongoose.Schema.Types.ObjectId, ref: "Sub" },
  // Assuming images is an array of file names or URLs
});
const Baloon = mongoose.model("Baloon", baloonSchema);

const subSchema = new mongoose.Schema({
  name: { type: String, required: true },
  // Assuming images is an array of file names or URLs
});
const Sub = mongoose.model("Sub", subSchema);

const sizeSchema = new mongoose.Schema({
  size: { type: String, required: false },
  price: { type: String, required: false },
  quantity: { type: String, required: false },
  baloonId: { type: mongoose.Schema.Types.ObjectId, ref: "Baloon" },
  // Assuming images is an array of file names or URLs
});
const Size = mongoose.model("Size", sizeSchema);

const cartSchema = new mongoose.Schema({
  baloonId: { type: mongoose.Schema.Types.ObjectId, ref: "Baloon" },
  accessId: { type: mongoose.Schema.Types.ObjectId, ref: "Access" },
  sizeId: { type: mongoose.Schema.Types.ObjectId, ref: "Size" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  orderId: { type: mongoose.Schema.Types.ObjectId, ref: "Order" },
  quantity: { type: String },
  status: { type: String }, // Assuming images is an array of file names or URLs
});
const Cart = mongoose.model("Cart", cartSchema);

const accessSchema = new mongoose.Schema({
  name: { type: String, required: false },
  image: { type: String, required: false },
  price: { type: String, required: false },
  quantity: { type: String, require: false },
  description: { type: String, require: false },
  description2: { type: String, require: false }, // Assuming images is an array of file names or URLs
});
const Access = mongoose.model("Access", accessSchema);

const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  status: { type: String, required: false },
  totalPrice: { type: String, required: false },
  createdAt: { type: Date, required: false }, // Assuming images is an array of file names or URLs
});
const Order = mongoose.model("Order", orderSchema);

const aboutSchema = new mongoose.Schema({
  about: { type: String, required: false },
  contact: { type: String, required: false }, // Assuming images is an array of file names or URLs
});
const About = mongoose.model("About", aboutSchema);

const paymentSchema = new mongoose.Schema({
  orderId: { type: String, required: false },
  userId: { type: String, required: false },
  amount: { type: String, required: false },
  status: { type: String, required: false }, // Assuming images is an array of file names or URLs
});
const Payment = mongoose.model("Payment", paymentSchema);

const userSchema = new mongoose.Schema({
  name: { type: String, required: false },
  email: { type: String, required: false },
  password: { type: String, required: false },
  image: { type: String, required: false }, // Assuming images is an array of file names or URLs
});
const User = mongoose.model("User", userSchema);

app.use(express.static(path.join(__dirname, "public")));
app.use(express.static("uploads"));

// Define a route to serve the login form
app.get("/admin-panel", (req, res) => {
  res.sendFile(path.join(__dirname, "login.html"));
});

const adminCredentials = {
  username: "admin",
  password: "adminpassword",
};

// Admin Login API
app.post("/admin-login", async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log(username, password);
    if (
      username === adminCredentials.username &&
      password === adminCredentials.password
    ) {
      // Set the admin user in the session
      req.session.user = { username: adminCredentials.username, role: "admin" };

      res.redirect("/baloons/foil");
    } else {
      res.status(401).json({ error: "Invalid admin credentials" });
    }
  } catch (error) {
    console.error("Error during admin login:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/logout", (req, res) => {
  // Destroy the session
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
      res.status(500).send("Internal Server Error");
    } else {
      res.redirect("/admin-panel"); // Redirect to the login page or any other page
    }
  });
});

// Middleware to verify admin session
const authenticateAdminSession = (req, res, next) => {
  if (req.session.user && req.session.user.role === "admin") {
    next();
  } else {
    //res.status(403).json({ error: "Forbidden" });
    res.redirect("/");
  }
};

// Admin-Only API Example
app.get("/admin-only", authenticateAdminSession, (req, res) => {
  res.status(200).json({ message: "Admin-only route accessed successfully" });
});

// MongoDB User Schema

app.set("view engine", "ejs"); // Set EJS as the view engine
app.set("views", __dirname + "/views");
app.get("/", (req, res) => {
  res.status(200).json({ message: "Admin-only route accessed successfully" });
});
app.get("/about", async (req, res) => {
  const successMessage = req.query.success;
  try {
    // Check if any record exists in the Hotel collection
    const existingAbout = await About.findOne();

    if (!existingAbout) {
      // If no record exists, create a new one
      const newAbout = new About({
        // Define properties for the new hotel as needed
        // For example:
        about: "",
        contact: "",
      });

      // Save the new hotel record
      await newAbout.save();

      // Render the detailEdit EJS template with the newly created hotel
      res.render("aboutEdit", { about: newAbout, successMessage });
    } else {
      // If a record exists, render the detailEdit EJS template with the existing hotel
      res.render("aboutEdit", {
        about: existingAbout,
        successMessage,
      });
    }
  } catch (error) {
    console.error("Error fetching about:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "uploads/");
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  },
});

const upload = multer({ storage: storage });
app.get("/baloons/:type", async (req, res) => {
  try {
    const successValue = req.query.success;
    const successMessage =
      successValue === "1"
        ? "Update successful!"
        : successValue === "2"
        ? "Stored successfully!"
        : successValue === "3"
        ? "Deleted successfully!"
        : successValue === "4"
        ? "Email already exists!"
        : null;
    const type = req.params.type;
    const baloons = await Baloon.find({ type: type });
    res.render("baloons", { baloons, successMessage, type }); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching baloons:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/baloon/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const uploadDirectory = path.join(__dirname, "uploads");
    const baloon = await Baloon.findById(id);
    const subs = await Sub.find({});
    res.render("baloonEdit", { baloon, uploadDirectory, subs }); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching baloon:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/baloons-create/:type", async (req, res) => {
  const lang = "italian";
  const type = req.params.type;
  const subs = await Sub.find({});
  res.render("baloonCreate", { subs, type });
});

app.post(
  "/store-baloon",
  upload.fields([{ name: "image", maxCount: 1 }]),
  async (req, res) => {
    try {
      const { name, price, color, size, quantity, type, subId } = req.body;

      // Extract file path from req.files object
      const imageFile = req.files["image"][0];
      const originalPath = imageFile.path;

      // Generate a unique name for the compressed image
      const uniqueImageName = `${uuidv4()}.jpg`;
      const compressedPath = path.join("uploads", uniqueImageName);

      // Compress the image using sharp
      await sharp(originalPath)
        .resize(500, 500, { fit: "inside" }) // Resize to max 500x500 pixels
        .jpeg({ quality: 70 }) // Set JPEG quality to 70%
        .toFile(compressedPath);

      // Save the unique image name in the database
      const newBaloon = new Baloon({
        name,
        price,
        color,
        size,
        quantity,
        type,
        subId,
        image: uniqueImageName,
      });

      // Save the new baloon document
      await newBaloon.save();

      // Delete the original image to save disk space
      fs.unlinkSync(originalPath);

      res.redirect("/baloons/" + type + "?success=2");
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  }
);
app.post(
  "/update-baloon/:id",
  upload.fields([{ name: "image", maxCount: 1 }]),
  async (req, res) => {
    try {
      const id = req.params.id;
      if (!id) {
        return res.status(400).json({ error: "id is required" });
      }
      const { name, price, color, size, quantity, subId } = req.body;
      // Find the room by ID
      const baloon = await Baloon.findById(id);

      if (!baloon) {
        return res.status(404).json({ error: "Baloon not found" });
      }

      if (name) {
        baloon.name = name;
      }
      if (price) {
        baloon.price = price;
      }

      if (color) {
        baloon.color = color;
      }
      if (size) {
        baloon.size = size;
      }
      if (quantity) {
        baloon.quantity = quantity;
      }
      if (subId) {
        baloon.subId = subId;
      }
      if (req.files["image"] && req.files["image"].length > 0) {
        // Assuming you want to store coverImage as a single file
        baloon.image = req.files["image"][0].filename; // Save the filename to the service object
      }

      // Save the updated room
      await baloon.save();

      res.redirect("/baloons/" + baloon.type + "?success=1");
    } catch (error) {
      console.error("Error updating baloon:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
);
app.get("/delete-baloon/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) {
      return res.status(400).json({ error: "id is required required" });
    }
    // Find the user by ID and delete
    const baloon = await Baloon.findByIdAndDelete(id);

    if (!baloon) {
      return res.status(404).json({ error: "Baloon not found" });
    }

    res.redirect("/baloons/" + baloon.type + "?success=3");
  } catch (error) {
    console.error("Error deleting baloon:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/access", async (req, res) => {
  try {
    const successValue = req.query.success;
    const successMessage =
      successValue === "1"
        ? "Update successful!"
        : successValue === "2"
        ? "Stored successfully!"
        : successValue === "3"
        ? "Deleted successfully!"
        : successValue === "4"
        ? "Email already exists!"
        : null;
    const access = await Access.find();
    res.render("access", { access, successMessage }); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching access:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/access/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const uploadDirectory = path.join(__dirname, "uploads");
    const access = await Access.findById(id);

    res.render("accessEdit", { access, uploadDirectory }); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching access:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/access-create", async (req, res) => {
  res.render("accessCreate", {});
});

app.post(
  "/store-access",
  upload.fields([{ name: "image", maxCount: 1 }]),
  async (req, res) => {
    try {
      const { name, price, quantity, description, description2 } = req.body;

      // Extract file paths from req.files object
      const image = req.files["image"][0].originalname;

      // Create a new Room document
      const newAccess = new Access({
        name,
        price,
        quantity,
        description,
        description2,
        image,
      });
      await newAccess.save();

      res.redirect("/access?success=2");
    } catch (error) {
      res.status(500).json({ error: error });
    }
  }
);
app.post(
  "/update-access/:id",
  upload.fields([{ name: "image", maxCount: 1 }]),
  async (req, res) => {
    try {
      const id = req.params.id;
      if (!id) {
        return res.status(400).json({ error: "id is required" });
      }
      const { name, price, quantity, description, description2 } = req.body;
      // Find the room by ID
      const access = await Access.findById(id);

      if (!access) {
        return res.status(404).json({ error: "Access not found" });
      }

      if (name) {
        access.name = name;
      }
      if (price) {
        access.price = price;
      }

      if (quantity) {
        access.quantity = quantity;
      }
      if (description) {
        access.description = description;
      }
      if (description2) {
        access.description2 = description2;
      }
      if (req.files["image"] && req.files["image"].length > 0) {
        // Assuming you want to store coverImage as a single file
        access.image = req.files["image"][0].filename; // Save the filename to the service object
      }

      // Save the updated room
      await access.save();

      res.redirect("/access?success=1");
    } catch (error) {
      console.error("Error updating access:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
);
app.get("/delete-access/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) {
      return res.status(400).json({ error: "id is required required" });
    }
    // Find the user by ID and delete
    const access = await Access.findByIdAndDelete(id);

    if (!access) {
      return res.status(404).json({ error: "Access not found" });
    }

    res.redirect("/access?success=3");
  } catch (error) {
    console.error("Error deleting access:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/sizes/:baloonId", async (req, res) => {
  try {
    const baloonId = req.params.baloonId;
    const sizes = await Size.find({ baloonId });
    const successValue = req.query.success;
    const successMessage =
      successValue === "1"
        ? "Update successful!"
        : successValue === "2"
        ? "Stored successfully!"
        : successValue === "3"
        ? "Deleted successfully!"
        : successValue === "4"
        ? "Email already exists!"
        : null;
    const baloon = await Baloon.findById(baloonId);

    res.render("sizes", { sizes, baloonId, successMessage, baloon }); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching subs:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/sizes-create/:baloonId", async (req, res) => {
  const baloonId = req.params.baloonId;
  const uniqueSizes = await Size.distinct("size");
  const baloon = await Baloon.findById(baloonId);

  res.render("sizeCreate", { baloonId, uniqueSizes, baloon });
});
app.get("/size/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const size = await Size.findById(id);
    const baloon = await Baloon.findById(size.baloonId);
    res.render("sizeEdit", { size, baloon }); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching subs:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/store-size", async (req, res) => {
  try {
    const { size, price, baloonId, quantity, sized } = req.body;
    console.log(req.body);
    if (sized) {
      si = sized;
    }
    if (!sized) {
      si = size;
    }

    // Extract file paths from req.files object

    // Create a new Room document
    const newSize = new Size({
      size: si,
      price,
      quantity,
      baloonId,
    });
    await newSize.save();

    res.redirect("/sizes/" + baloonId + "?success=2");
  } catch (error) {
    res.status(500).json({ error: error });
  }
});
app.post("/update-size/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) {
      return res.status(400).json({ error: "id is required" });
    }
    const { size, price, quantity } = req.body;
    // Find the room by ID
    const siz = await Size.findById(id);

    if (!siz) {
      return res.status(404).json({ error: "Siz not found" });
    }

    if (size) {
      siz.size = size;
    }
    if (price) {
      siz.price = price;
    }
    if (quantity) {
      siz.quantity = quantity;
    }

    // Save the updated room
    await siz.save();

    res.redirect("/sizes/" + siz.baloonId + "?success=1");
  } catch (error) {
    console.error("Error updating sub:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/delete-size/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) {
      return res.status(400).json({ error: "id is required required" });
    }
    // Find the user by ID and delete
    const sub = await Size.findByIdAndDelete(id);

    if (!sub) {
      return res.status(404).json({ error: "sub not found" });
    }

    res.redirect("/sizes/" + sub.baloonId + "?success=3");
  } catch (error) {
    console.error("Error deleting sub:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/subs", async (req, res) => {
  try {
    const successValue = req.query.success;
    const successMessage =
      successValue === "1"
        ? "Update successful!"
        : successValue === "2"
        ? "Stored successfully!"
        : successValue === "3"
        ? "Deleted successfully!"
        : successValue === "4"
        ? "Email already exists!"
        : null;

    const subs = await Sub.find({});
    res.render("subs", { subs, successMessage }); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching abouts:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/sub/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const sub = await Sub.findById(id);
    console.log("here" + sub);
    res.render("subEdit", { sub }); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching subs:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/subs-create", (req, res) => {
  res.render("subCreate");
});
app.post("/store-sub", async (req, res) => {
  try {
    const { name } = req.body;
    console.log(req.body);

    // Extract file paths from req.files object

    // Create a new Room document
    const newSub = new Sub({
      name,
    });
    await newSub.save();

    res.redirect("/subs?success=2");
  } catch (error) {
    res.status(500).json({ error: error });
  }
});
app.post("/update-sub/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) {
      return res.status(400).json({ error: "id is required" });
    }
    const { name } = req.body;
    // Find the room by ID
    const sub = await Sub.findById(id);

    if (!sub) {
      return res.status(404).json({ error: "Sub not found" });
    }

    if (name) {
      sub.name = name;
    }

    // Save the updated room
    await sub.save();

    res.redirect("/subs?success=1");
  } catch (error) {
    console.error("Error updating sub:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/delete-sub/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) {
      return res.status(400).json({ error: "id is required required" });
    }
    // Find the user by ID and delete
    const sub = await Sub.findByIdAndDelete(id);

    if (!sub) {
      return res.status(404).json({ error: "sub not found" });
    }

    res.redirect("/subs?success=3");
  } catch (error) {
    console.error("Error deleting sub:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

//users
app.get("/users", async (req, res) => {
  try {
    const lang = "italian";
    const successValue = req.query.success;
    const successMessage =
      successValue === "1"
        ? "Update successful!"
        : successValue === "2"
        ? "Stored successfully!"
        : successValue === "3"
        ? "Deleted successfully!"
        : successValue === "4"
        ? "Email already exists!"
        : null;

    const users = await User.find({});
    res.render("users", { users, successMessage }); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/user/:id", async (req, res) => {
  try {
    const lang = "italian";
    const id = req.params.id;
    const user = await User.findById(id);
    console.log("here" + user);
    res.render("userEdit", { user, lang }); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
// Logout API (optional if you want to invalidate tokens on the server)
// You can also rely on client-side token handling for logout

// Middleware to verify the token
const authenticateToken = (req, res, next) => {
  const token = req.header("Authorization");

  if (!token) return res.status(401).json({ error: "Unauthorized" });

  jwt.verify(token, "your-secret-key", (err, user) => {
    if (err) return res.status(403).json({ error: "Forbidden" });

    req.user = user;
    next();
  });
};

app.post("/update-about/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) {
      return res.status(400).json({ error: "id is required" });
    }
    const { about, contact } = req.body;
    //const { name, price, description, capacity } = req.body;
    // Find the room by ID
    const abt = await About.findById(id);

    if (!abt) {
      return res.status(404).json({ error: "About not found" });
    }

    if (about) {
      abt.about = about;
    }
    if (contact) {
      abt.contact = contact;
    }

    // Save the updated room
    await abt.save();

    res.redirect("/about?success=Updated-Successfully");
  } catch (error) {
    console.error("Error updating hotel:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
// Logout API
app.post("/logout", authenticateToken, (req, res) => {
  // This is where you can perform logout operations if needed
  res.status(200).json({ message: "Logout successful" });
});

app.post(
  "/update-user/:id",
  upload.fields([{ name: "image", maxCount: 1 }]),
  async (req, res) => {
    try {
      const id = req.params.id;
      if (!id) {
        return res.status(400).json({ error: "id is required" });
      }
      const { name, password } = req.body;
      // Find the service by ID
      const user = await User.findById(id);

      if (!user) {
        return res.status(404).json({ error: "User not found" });
      }

      if (name) {
        user.name = name;
      }

      if (password) {
        user.password = password;
      }
      // Check if coverImage is uploaded
      if (req.files["image"] && req.files["image"].length > 0) {
        // Assuming you want to store coverImage as a single file
        user.image = req.files["image"][0].filename; // Save the filename to the service object
      }

      // Save the updated service
      await user.save();

      res.redirect("/users?success=1");
    } catch (error) {
      console.error("Error updating user:", error);
      res.status(500).json({ error: "Internal Server Error" });
    }
  }
);
app.post("update-user-api", async (req, res) => {
  try {
    const { name, password, email } = req.body;
    // Find the service by ID
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (name) {
      user.name = name;
    }

    if (password) {
      user.password = password;
    }

    // Save the updated service
    await user.save();

    res.json({ user: user });
  } catch (error) {
    console.error("Error updating user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/delete-user/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) {
      return res.status(400).json({ error: "id is required required" });
    }
    // Find the user by ID and delete
    const user = await User.findByIdAndDelete(id);

    if (!user) {
      return res.status(404).json({ error: "user not found" });
    }

    res.redirect("/users?success=3");
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/orders", async (req, res) => {
  try {
    const lang = "italian";
    const successValue = req.query.success;
    const successMessage =
      successValue === "1"
        ? "Update successful!"
        : successValue === "2"
        ? "Stored successfully!"
        : successValue === "3"
        ? "Deleted successfully!"
        : successValue === "4"
        ? "Email already exists!"
        : null;

    const orders = await Order.find({});
    res.render("orders", { orders, successMessage, lang }); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/orders/:userId", async (req, res) => {
  try {
    const userId = req.params.userId;
    const lang = "italian";
    const orders = await Order.find({ userId });
    const successMessage = null;
    res.render("orders", { orders, successMessage }); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/order/:id", async (req, res) => {
  try {
    const lang = "italian";
    const id = req.params.id;
    const order = await Order.findById(id);
    const baloons = await Baloon.find({});
    const access = await Access.find({});
    const users = await User.find({});
    console.log("here" + order);
    res.render("orderEdit", { order, access, baloons, users, lang }); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching orders:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/orders-create", async (req, res) => {
  const lang = "italian";
  const access = await Access.find({});
  const baloons = await Baloon.find({});
  const users = await User.find({});

  res.render("orderCreate", { access, baloons, users });
});
app.get("/carts/:orderId", async (req, res) => {
  const lang = "italian";
  const orderId = req.params.orderId;
  const successValue = req.query.success;
  const successMessage =
    successValue === "1"
      ? "Update successful!"
      : successValue === "2"
      ? "Stored successfully!"
      : successValue === "3"
      ? "Deleted successfully!"
      : successValue === "4"
      ? "Email already exists!"
      : null;
  const carts = await Cart.find({ orderId })
    .populate("accessId")
    .populate("baloonId");
  console.log(carts);
  res.render("carts", { carts, successMessage, orderId });
});
app.get("/carts-create/:orderId", async (req, res) => {
  const lang = "italian";
  const orderId = req.params.orderId;
  const baloons = await Baloon.find({});
  const access = await Access.find({});
  res.render("cartCreate", { orderId, baloons, access });
});
app.post("/store-cart", async (req, res) => {
  try {
    const { baloonId, accessId, quantity, orderId } = req.body;
    console.log(req.body);
    const cart = new Cart({
      baloonId,
      accessId,
      quantity,
      orderId,
    });
    await cart.save();
    res.redirect("/carts/" + orderId + "/?success=2");
  } catch (error) {
    res.status(500).json({ error: error });
  }
});
app.post("/store-order", async (req, res) => {
  try {
    const { userId, status } = req.body;
    console.log(req.body);
    const order = new Order({
      userId,
      status,
    });
    await order.save();
    res.redirect("/orders?success=2");
  } catch (error) {
    res.status(500).json({ error: error });
  }
});

app.post("/update-order/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) {
      return res.status(400).json({ error: "id is required" });
    }
    const { userId, status } = req.body;
    console.log(userId);
    // Find the service by ID
    const order = await Order.findById(id);

    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    if (userId) {
      order.userId = userId;
    }
    if (status) {
      order.status = status;
    }

    // Save the updated service
    await order.save();

    res.redirect("/orders?success=1");
  } catch (error) {
    console.error("Error updating order:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/delete-order/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) {
      return res.status(400).json({ error: "id is required" });
    }
    // Find the user by ID and delete
    const order = await Order.findByIdAndDelete(id);

    if (!order) {
      return res.status(404).json({ error: "order not found" });
    }

    res.redirect("/orders?success=3");
  } catch (error) {
    console.error("Error deleting order:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.get("/delete-cart/:id", async (req, res) => {
  try {
    const id = req.params.id;
    if (!id) {
      return res.status(400).json({ error: "id is required" });
    }
    // Find the user by ID and delete
    const order = await Cart.findByIdAndDelete(id);

    if (!order) {
      return res.status(404).json({ error: "cart not found" });
    }

    res.redirect("/carts/" + order._id + "/?success=3");
  } catch (error) {
    console.error("Error deleting order:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/add-to-cart", async (req, res) => {
  try {
    const { baloonId, accessId, quantity, sizeId, userId } = req.body;
    console.log(req.body);
    const cart = new Cart({
      baloonId,
      accessId,
      quantity,
      sizeId,
      userId,
      status: "active",
    });
    await cart.save();
    res.json({ message: "added to cart successfully" });
  } catch (error) {
    res.status(500).json({ error: error });
  }
});
app.post("/edit-cart", async (req, res) => {
  try {
    const { cartId, quantity } = req.body;

    // Find the cart item by cartId
    const cartItem = await Cart.findById(cartId);

    if (!cartItem) {
      return res.status(404).json({ message: "Cart item not found" });
    }

    // Update the quantity
    cartItem.quantity = quantity;

    // Save the updated cart item
    await cartItem.save();

    res.json({ message: "Cart item updated successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/remove-from-cart", async (req, res) => {
  try {
    const { cartId } = req.body;
    // Find the user by ID and delete
    const order = await Cart.findByIdAndDelete(cartId);

    if (!order) {
      return res.status(404).json({ error: "cart not found" });
    }

    res.json({ message: "removed successfully" });
  } catch (error) {
    console.error("Error deleting order:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/get-user-cart", async (req, res) => {
  try {
    const { userId } = req.body;
    const baloons = await Cart.find({ userId })
      .populate("accessId")
      .populate("baloonId")
      .populate("sizeId")
      .exec();

    var totalPrice = 0;
    // Calculate the total price
    for (const item of baloons) {
      if (item.accessId) {
        const access = await Access.findById(item.accessId._id);
        totalPrice += access.price * item.quantity;
      }
      if (item.sizeId) {
        const size = await Size.findById(item.sizeId._id);
        totalPrice += size.price * item.quantity;
      }
      if (item.sizeId == null && item.baloonId) {
        const baloon = await Baloon.findById(item.baloonId._id);
        totalPrice += baloon.price * item.quantity;
      }
    }

    res.json({ carts: baloons, totalPrice: totalPrice }); // Pass the rooms data with attached service documents to the client
  } catch (error) {
    console.error("Error fetching baloons:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/checkout", async (req, res) => {
  try {
    const { userId } = req.body;

    // Fetch active cart items for the user
    const cartItems = await Cart.find({ userId, status: "active" });

    if (cartItems.length === 0) {
      return res.status(400).json({ message: "No items in cart" });
    }

    let totalPrice = 0;

    // Calculate the total price
    for (const item of cartItems) {
      if (item.accessId) {
        const access = await Access.findById(item.accessId);
        totalPrice += access.price * item.quantity;
      }
      if (item.sizeId) {
        const size = await Size.findById(item.sizeId);
        totalPrice += size.price * item.quantity;
      }
      if (item.sizeId == null && item.baloonId) {
        const baloon = await Baloon.findById(item.baloonId);
        totalPrice += baloon.price * item.quantity;
      }
    }

    // Create a new order
    const order = new Order({
      userId,
      totalPrice,
      status: "pending", // Assuming you have order statuses like pending, completed, etc.
      createdAt: new Date(),
    });
    await order.save();

    // Associate orderId with each cart item and update their status
    await Cart.updateMany(
      { userId, status: "active" },
      { $set: { orderId: order._id, status: "ordered" } }
    );

    res.json({ message: "Checkout successful", orderId: order._id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
app.get("/get-about", async (req, res) => {
  try {
    // Check if any record exists in the Hotel collection
    const existingAbout = await About.findOne();

    res.json(existingAbout);
  } catch (error) {
    console.error("Error fetching about:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/get-baloons", async (req, res) => {
  try {
    const { type } = req.body;
    const baloons = await Baloon.find({ type }).populate("subId").exec();

    res.json(baloons); // Pass the rooms data with attached service documents to the client
  } catch (error) {
    console.error("Error fetching baloons:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/get-baloons-by-sub", async (req, res) => {
  try {
    const { subId } = req.body;
    const baloons = await Baloon.find({ subId });

    res.json(baloons); // Pass the rooms data with attached service documents to the client
  } catch (error) {
    console.error("Error fetching baloons:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/get-subs", async (req, res) => {
  try {
    const baloons = await Sub.find({});

    res.json(baloons); // Pass the rooms data with attached service documents to the client
  } catch (error) {
    console.error("Error fetching baloons:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const usr = await User.findOne({ email: email, password: password });
    res.json(usr);
  } catch (error) {
    res.status(500).json({ error: error });
  }
});
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const usr = new User({
      name,
      email,
      password,
    });
    await usr.save();
    res.json("stored successfully");
  } catch (error) {
    res.status(500).json({ error: error });
  }
});
app.post("/get-baloons", async (req, res) => {
  try {
    const { type } = req.body;
    const baloons = await Baloon.find({ type });
    res.json(baloons); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching checks:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/get-sizes", async (req, res) => {
  try {
    const { baloonId } = req.body;
    const sizes = await Size.find({ baloonId });
    res.json(sizes); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching checks:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/get-access", async (req, res) => {
  try {
    const access = await Access.find({});
    res.json(access); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching checks:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/get-about", async (req, res) => {
  try {
    const abouts = await About.find({});
    res.json(abouts); // Pass the users data to the EJS template
  } catch (error) {
    console.error("Error fetching checks:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});
app.post("/get-orders-with-carts/:userId", async (req, res) => {
  try {
    const { userId } = req.params;

    // Fetch orders for the given user
    const orders = await Order.find({ userId });

    if (orders.length === 0) {
      return res.status(404).json({ message: "No orders found for this user" });
    }

    // For each order, fetch associated carts
    const ordersWithCarts = await Promise.all(
      orders.map(async (order) => {
        const carts = await Cart.find({ orderId: order._id })
          .populate("accessId")
          .populate("baloonId")
          .populate("sizeId")
          .exec();
        return { ...order.toObject(), carts };
      })
    );

    res.json(ordersWithCarts);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
app.post("/store-order-mobile", async (req, res) => {
  try {
    const { userId, status, carts } = req.body;

    const order = new Order({
      userId,
      status,
    });
    await order.save();
    await Promise.all(
      carts.map(async (cart) => {
        const crt = new Cart({
          accessId: cart["accessId"],
          baloonId: cart["baloonId"],
          quantity: cart["quantity"],
          orderId: order._id,
        });
        await crt.save();
      })
    );
    console.log("here");
    res.json({ orderId: order._id });
  } catch (error) {
    res.status(500).json({ error: error });
  }
});
app.get("/payment/:userId/:orderId/:amount", async (req, res) => {
  const userId = req.params.userId;
  const orderId = req.params.orderId;
  const amount = req.params.amount;
  res.render("payment", { userId, orderId, amount });
});
app.get("/success", async (req, res) => {
  res.render("success", {});
});
app.get("/error", async (req, res) => {
  res.render("error", {});
});
app.get("/payments", async (req, res) => {
  const payments = await Payment.find({}).populate("userId").exec();
  res.render("payments", { payments });
});
app.post("/create-charge", async (req, res) => {
  const { token, amount, userId, orderId } = req.body;

  if (!token) {
    return res.status(400).json({ message: "Unable to create stripe token" });
  }

  try {
    // Charge the card directly using the token
    const charge = await stripe.charges.create({
      amount: amount, // Amount in cents
      currency: "usd",
      description: "Example charge",
      source: token, // Use the token directly
    });
    if (charge && charge["status"] == "succeeded") {
      const payment = new Payment({
        userId,
        orderId,
        amount,
        status: "success",
      });
      await payment.save();
      return res.status(200).json({ message: "success", charge });
    }
    if (!charge || charge["status"] != "succeeded") {
      const payment = new Payment({
        userId,
        orderId,
        amount,
        status: "error",
      });
      await payment.save();
      return res.status(200).json({ message: "error", charge });
    }
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});
const server = http.createServer(app);

server.listen(3000, () => {
  console.log("Server running on port 3000");
});
