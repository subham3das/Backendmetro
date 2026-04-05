const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const { OAuth2Client } = require("google-auth-library");
require("dotenv").config();
const cloudinary = require('cloudinary').v2;

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});
const app = express();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);

// Optimized Middleware
app.use(cors());
app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));

// Database Handshake
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ Database Uplink Established"))
    .catch(err => console.error("❌ Database Connection Failed:", err));

// --- DATABASE MODELS ---

const Collection = mongoose.model("Collection", new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    isActive: { type: Boolean, default: true },
}));

const Category = mongoose.model("Category", new mongoose.Schema({
    name: { type: String, required: true },
    parentCollection: { type: mongoose.Schema.Types.ObjectId, ref: "Collection", required: true },
}));

const Product = mongoose.model("Product", new mongoose.Schema({
    name: String,
    description: String,
    mrp: Number,
    salePrice: Number,
    stock: Object, 
    colors: Array,
    media: Array, 
    collectionId: { type: mongoose.Schema.Types.ObjectId, ref: "Collection" },
    categoryId: { type: mongoose.Schema.Types.ObjectId, ref: "Category" },
    tags: String,
    isArchived: { type: Boolean, default: false }, 
    dateDeployed: { type: Date, default: Date.now },
    reviews: [{
        userId: mongoose.Schema.Types.ObjectId,
        userName: String,
        rating: Number,
        text: String,
        date: { type: Date, default: Date.now }
    }]
}));

const User = mongoose.model("User", new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: "citizen" },
    isVerified: { type: Boolean, default: true },
    dateJoined: { type: Date, default: Date.now }
}));

// ISOLATED ADMIN MODEL
const Admin = mongoose.model("Admin", new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
}), "admin"); 

const Order = mongoose.model("Order", new mongoose.Schema({
    userId: mongoose.Schema.Types.ObjectId,
    items: Array,
    address: Object,
    totalAmount: Number,
    paymentMethod: String,
    status: { type: String, default: "Progress" }, 
    trackingLink: { type: String, default: "" },   
    date: { type: Date, default: Date.now }
}));

const Coupon = mongoose.model("Coupon", new mongoose.Schema({
    code: { type: String, required: true, unique: true },
    type: { type: String, enum: ['percentage', 'flat'], default: 'flat' },
    value: { type: Number, required: true },
    startDate: Date,
    endDate: Date,
    totalLimit: { type: Number, default: 100 },
    userLimit: { type: Number, default: 1 },
    minCart: { type: Number, default: 0 },
    usedCount: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true }
}));

const Hero = mongoose.model("Hero", new mongoose.Schema({
    mediaUrl: String,
    mediaType: { type: String, enum: ['image', 'video'] },
    productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
    slot: { type: Number, unique: true } 
}));

// --- UPDATED ADMIN GUARD: HANDSHAKES WITH THE PRIVATE ADMIN COLLECTION ---
const adminGuard = async (req, res, next) => {
    const adminId = req.headers['admin-signal']; 
    if (!adminId) return res.status(401).json({ error: "ACCESS DENIED: NO SIGNAL" });

    try {
        // We now check the Admin collection specifically
        const admin = await Admin.findById(adminId);
        if (admin) {
            next();
        } else {
            res.status(403).json({ error: "FORBIDDEN: ADMIN CLEARANCE REQUIRED" });
        }
    } catch (e) { res.status(500).json({ error: "Guard System Fault" }); }
};

const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "metroclassy1223@gmail.com", 
        pass: "rkgu mjzy mfgo uhjr" 
    }
});

const otpVault = new Map();

// ROUTE: Request Password Reset
app.post("/api/auth/forgot-password", async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ error: "Identity not found." });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpVault.set(email, { otp, expires: Date.now() + 600000 });

        transporter.sendMail({
            from: '"METROCLASSY HQ" <metroclassy1223@gmail.com>',
            to: email,
            subject: "PASSWORD RESET SIGNAL",
            html: `<h1>VERIFICATION CODE: ${otp}</h1>`
        }).catch(err => console.error("Background Mail Error:", err)); 

        res.json({ success: true, message: "Transmission initiated." });
    } catch (err) { res.status(500).json({ error: "Internal Error" }); }
});

// ROUTE: Verify OTP & Update Password
app.post("/api/auth/reset-password", async (req, res) => {
    const { email, otp, newPassword } = req.body;
    const record = otpVault.get(email);

    if (!record || record.otp !== otp || Date.now() > record.expires) {
        return res.status(400).json({ error: "Invalid or expired signal." });
    }

    try {
        await User.findOneAndUpdate({ email }, { password: newPassword });
        otpVault.delete(email); 
        res.json({ success: true, message: "Credentials Updated." });
    } catch (err) { res.status(500).json({ error: "Vault Update Failed" }); }
});

// --- SECTOR DATA HANDSHAKE ---
app.get("/api/sector-data", async (req, res) => {
    try {
        const [collections, categories, coupons] = await Promise.all([
            Collection.find(),
            Category.find().populate("parentCollection"),
            Coupon.find().sort({ endDate: -1 })
        ]);
        res.json({ collections, categories, coupons });
    } catch (err) { 
        res.status(500).json({ error: "Sector Data Signal Lost" }); 
    }
});

// --- AUTHENTICATION PROTOCOLS ---

app.post("/api/auth/google", async (req, res) => {
    try {
        const { token } = req.body;
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        
        let user = await User.findOne({ email: payload.email });
        if (!user) {
            user = new User({
                name: payload.name,
                email: payload.email,
                password: "GOOGLE_AUTH_USER",
                role: "citizen",
                isVerified: true
            });
            await user.save();
        }
        res.json({ success: true, user: { name: user.name, email: user.email, role: user.role, id: user._id } });
    } catch (err) { res.status(401).json({ error: "Google Auth Failed" }); }
});

app.post("/api/auth/signup", async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const existing = await User.findOne({ email });
        if (existing) return res.status(400).json({ error: "Comm-link already in archives." });
        const newUser = new User({ name, email, password, isVerified: true });
        await newUser.save();
        res.status(201).json({ success: true, user: { name: newUser.name, email: newUser.email, role: newUser.role, id: newUser._id } });
    } catch (err) { res.status(400).json({ error: "Enlistment Failure" }); }
});

// REFINED ADMIN LOGIN: No longer creates entries in the 'users' collection
app.post("/api/auth/admin-login", async (req, res) => {
    try {
        const { email, password, secureCode } = req.body;
        const MASTER_SECURE_CODE = "774921";

        const adminRecord = await Admin.findOne({ email });
        
        if (adminRecord && adminRecord.password === password) {
            if (!secureCode || secureCode !== MASTER_SECURE_CODE) {
                return res.status(403).json({ error: "SECURE CODE REQUIRED", step: 2 });
            }
            // Returns directly from Admin record, no User table synchronization
            return res.json({ 
                success: true, 
                user: { 
                    name: "Admin_Root", 
                    email: adminRecord.email, 
                    role: "admin", 
                    id: adminRecord._id 
                } 
            });
        }
        res.status(401).json({ error: "INVALID IDENTITY" });
    } catch (err) { res.status(500).json({ error: "Vault Offline" }); }
});

app.post("/api/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Handshake with the User archives
        const user = await User.findOne({ email, password });
        
        // 2. If no user found, deny access
        if (!user) return res.status(401).json({ error: "Invalid Credentials" });
        
        // 3. TACTICAL LOCK: If the role is 'admin', reject the signal for this terminal
        if (user.role === 'admin') {
            return res.status(403).json({ 
                error: "ADMIN CLEARANCE DETECTED: Use the Admin Terminal to log in." 
            });
        }

        // 4. Grant access only to regular citizens
        res.json({ 
            success: true, 
            user: { name: user.name, email: user.email, role: user.role, id: user._id } 
        });
    } catch (err) { 
        res.status(500).json({ error: "Vault Communication Error" }); 
    }
});

// --- FEEDBACK ENGINE ---

app.post("/api/products/:id/reviews", async (req, res) => {
    try {
        const { userId, userName, rating, text } = req.body;
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ error: "Gear Not Found" });
        product.reviews.unshift({ userId, userName, rating, text });
        await product.save();
        res.json(product);
    } catch (err) { res.status(500).json({ error: "Feedback Sync Failed" }); }
});

// --- ADMIN MODERATION (SECURED) ---

app.get("/api/admin/all-reviews", adminGuard, async (req, res) => {
    try {
        const products = await Product.find({}, 'name reviews');
        let allReviews = [];
        products.forEach(p => {
            if (p.reviews) {
                p.reviews.forEach(r => {
                    allReviews.push({
                        productId: p._id,
                        productName: p.name,
                        reviewId: r._id,
                        userName: r.userName,
                        rating: r.rating,
                        text: r.text,
                        date: r.date
                    });
                });
            }
        });
        res.json(allReviews.sort((a, b) => new Date(b.date) - new Date(a.date)));
    } catch (err) { res.status(500).json({ error: "Moderation Signal Lost" }); }
});

app.delete("/api/admin/products/:pid/reviews/:rid", adminGuard, async (req, res) => {
    try {
        const product = await Product.findById(req.params.pid);
        product.reviews = product.reviews.filter(r => r._id.toString() !== req.params.rid);
        await product.save();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: "Termination Failed" }); }
});

// --- INVENTORY & DEPLOYMENT ---

app.post("/api/orders/deploy", async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const { items, address, totalAmount, paymentMethod, userId, couponCode } = req.body;
        const order = new Order({ userId, items, address, totalAmount, paymentMethod });
        await order.save({ session });

        for (const item of items) {
            const product = await Product.findById(item.id || item._id).session(session);
            if (product && product.stock) {
                const size = item.size;
                if (product.stock[size] !== undefined) {
                    const currentStock = product.stock[size];
                    const requestedQty = item.quantity || 1;
                    if (currentStock < requestedQty) throw new Error(`Insufficient stock for ${product.name}`);
                    product.stock[size] = currentStock - requestedQty;
                    product.markModified('stock'); 
                    await product.save({ session });
                }
            }
        }

        if (couponCode) {
            await Coupon.findOneAndUpdate({ code: couponCode.toUpperCase() }, { $inc: { usedCount: 1 } }, { session });
        }

        await session.commitTransaction();
        session.endSession();
        res.status(201).json({ success: true, orderId: order._id });
    } catch (err) {
        await session.abortTransaction();
        session.endSession();
        res.status(400).json({ error: err.message });
    }
});

// --- ADMIN ANALYTICS (SECURED) ---

app.get("/api/admin/hq-stats", adminGuard, async (req, res) => {
    try {
        const [orders, gearCount, citizenCount] = await Promise.all([
            Order.aggregate([{ $match: { status: { $ne: "Aborted" } } }, { $group: { _id: null, total: { $sum: "$totalAmount" } } }]),
            Product.countDocuments({ isArchived: false }),
            User.countDocuments()
        ]);
        res.json({
            revenue: orders[0]?.total || 0,
            gear: gearCount,
            citizens: citizenCount,
            recentOrders: await Order.find().sort({ date: -1 }).limit(5)
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- VAULT MANAGEMENT ---

app.get("/api/products", async (req, res) => {
    try {
        let query = { isArchived: false }; 
        if (req.query.search) query.name = { $regex: req.query.search, $options: 'i' };
        if (req.query.collection) query.collectionId = req.query.collection;
        if (req.query.category) query.categoryId = req.query.category;
        let sort = req.query.sort === 'price-low' ? { salePrice: 1 } : req.query.sort === 'price-high' ? { salePrice: -1 } : { dateDeployed: -1 };
        const products = await Product.find(query).populate("collectionId categoryId").sort(sort);
        res.json(products);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/products/:id", async (req, res) => {
    try {
        const product = await Product.findById(req.params.id).populate("collectionId categoryId");
        res.json(product);
    } catch (err) { res.status(404).json({ error: "Gear Not Found" }); }
});

app.get("/api/heroes", async (req, res) => {
    try {
        const heroes = await Hero.find().populate("productId").sort({ slot: 1 });
        res.json(heroes);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/track/:id", async (req, res) => {
    try {
        const { id } = req.params;
        let order;
        if (id.length === 24) {
            order = await Order.findById(id).lean();
        }
        if (!order) {
            const allOrders = await Order.find().lean();
            order = allOrders.find(o => o._id.toString().toUpperCase().endsWith(id.toUpperCase()));
        }
        if (!order) return res.status(404).json({ error: "Signal Not Found" });
        res.json(order);
    } catch (err) { res.status(500).json({ error: "Track Signal Lost" }); }
});

app.patch("/api/orders/:id/abort", async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const { id } = req.params;
        const { userId } = req.body;
        const order = await Order.findOne({ _id: id, userId: userId }).session(session);
        
        if (!order) {
            await session.abortTransaction();
            return res.status(403).json({ error: "UNAUTHORIZED: Access Denied" });
        }

        if (order.status !== 'Progress') {
            await session.abortTransaction();
            return res.status(400).json({ error: "ABORT FAILED: Mission already in transit" });
        }

        for (const item of order.items) {
            const product = await Product.findById(item.id || item._id).session(session);
            if (product && product.stock && product.stock[item.size] !== undefined) {
                product.stock[item.size] += (item.quantity || 1);
                product.markModified('stock');
                await product.save({ session });
            }
        }

        order.status = 'Aborted';
        await order.save({ session });
        await session.commitTransaction();
        res.json({ success: true, message: "MISSION TERMINATED & ASSETS RESTORED" });
    } catch (err) {
        await session.abortTransaction();
        res.status(500).json({ error: "Abort signal lost" });
    } finally {
        session.endSession();
    }
});

// --- ADMIN CONTROL ROUTES ---

app.post("/api/collections", adminGuard, async (req, res) => { const col = new Collection(req.body); await col.save(); res.json(col); });
app.delete("/api/collections/:id", adminGuard, async (req, res) => { await Category.deleteMany({ parentCollection: req.params.id }); await Collection.findByIdAndDelete(req.params.id); res.json({ success: true }); });
app.post("/api/categories", adminGuard, async (req, res) => { const cat = new Category(req.body); await cat.save(); res.json(cat); });
app.delete("/api/categories/:id", adminGuard, async (req, res) => { await Category.findByIdAndDelete(req.params.id); res.json({ success: true }); });
app.post("/api/admin/deploy", adminGuard, async (req, res) => { 
    try {
        const body = req.body;
        if (body.media && Array.isArray(body.media)) {
            for (let i = 0; i < body.media.length; i++) {
                if (body.media[i].url && body.media[i].url.startsWith("data:")) {
                    const uploadRes = await cloudinary.uploader.upload(body.media[i].url, { folder: "metroclassy/products" });
                    body.media[i].url = uploadRes.secure_url;
                }
            }
        }
        const p = new Product(body); 
        await p.save(); 
        res.status(201).json({ success: true }); 
    } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get("/api/admin/all-products", adminGuard, async (req, res) => { res.json(await Product.find().populate("collectionId categoryId").sort({ dateDeployed: -1 })); });
app.put("/api/admin/products/:id", adminGuard, async (req, res) => { 
    try {
        const body = req.body;
        if (body.media && Array.isArray(body.media)) {
            for (let i = 0; i < body.media.length; i++) {
                if (body.media[i].url && body.media[i].url.startsWith("data:")) {
                    const uploadRes = await cloudinary.uploader.upload(body.media[i].url, { folder: "metroclassy/products" });
                    body.media[i].url = uploadRes.secure_url;
                }
            }
        }
        res.json(await Product.findByIdAndUpdate(req.params.id, body, { new: true })); 
    } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete("/api/admin/products/:id", adminGuard, async (req, res) => { try { await Product.findByIdAndDelete(req.params.id); res.json({ success: true }); } catch (e) { res.status(500).send(e); } });
app.post("/api/admin/coupons", adminGuard, async (req, res) => { const cp = new Coupon(req.body); await cp.save(); res.status(201).json(cp); });
app.delete("/api/admin/coupons/:id", adminGuard, async (req, res) => { try { await Coupon.findByIdAndDelete(req.params.id); res.json({ success: true }); } catch (e) { res.status(500).send(e); } });
app.post("/api/validate-coupon", async (req, res) => {
    try {
        const { code, cartValue } = req.body;
        const coupon = await Coupon.findOne({ code: code.toUpperCase(), isActive: true });
        if (!coupon) return res.status(400).json({ valid: false, message: "SIGNAL NOT FOUND" });
        if (coupon.usedCount >= coupon.totalLimit) return res.status(400).json({ valid: false, message: "VOUCHER DEPLETED" });
        if (cartValue < coupon.minCart) return res.status(400).json({ valid: false, message: `MINIMUM ₹${coupon.minCart} REQUIRED` });
        res.json({ valid: true, discount: coupon.value, type: coupon.type });
    } catch (err) { res.status(500).json({ error: "Validation Interrupted" }); }
});
app.post("/api/admin/hero-deploy", adminGuard, async (req, res) => { 
    try {
        let { mediaUrl, mediaType, productId, slot } = req.body; 
        if (mediaUrl && mediaUrl.startsWith("data:")) {
            const uploadRes = await cloudinary.uploader.upload(mediaUrl, { folder: "metroclassy/heroes" });
            mediaUrl = uploadRes.secure_url;
        }
        await Hero.findOneAndUpdate({ slot }, { mediaUrl, mediaType, productId, slot }, { upsert: true, new: true }); 
        res.json({ success: true }); 
    } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete("/api/admin/hero/:slot", adminGuard, async (req, res) => { await Hero.findOneAndDelete({ slot: req.params.slot }); res.json({ success: true }); });
app.get("/api/admin/orders", adminGuard, async (req, res) => { res.json(await Order.find().sort({ date: -1 })); });
app.patch("/api/admin/orders/:id/status", adminGuard, async (req, res) => { res.json(await Order.findByIdAndUpdate(req.params.id, req.body, { new: true })); });
app.patch("/api/admin/orders/:id/link", adminGuard, async (req, res) => { res.json(await Order.findByIdAndUpdate(req.params.id, { trackingLink: req.body.link }, { new: true })); });
app.delete("/api/admin/orders/:id", adminGuard, async (req, res) => { await Order.findByIdAndDelete(req.params.id); res.json({ success: true }); });

app.get("/api/orders/user/:userId", async (req, res) => {
    try {
        const missions = await Order.find({ userId: req.params.userId }).sort({ date: -1 }).lean();
        res.json(missions);
    } catch (err) { res.status(500).json({ error: "Signal Lost" }); }
});

app.listen(5000, () => console.log("🚀 Syndicate Hangar Online | Port 5000"));

