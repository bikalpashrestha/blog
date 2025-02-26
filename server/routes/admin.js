const express = require('express');
const router = express.Router();
const Post = require('../models/Post');
const User = require('../models/User');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const methodOverride = require('method-override');

const adminLayout = '../views/layouts/admin';
const jwtSecret = process.env.JWT_SECRET;

/* Middleware */
router.use(methodOverride('_method'));

/* Authentication Middleware */
const authMiddleware = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }
    try {
        const decoded = jwt.verify(token, jwtSecret);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Unauthorized' });
    }
};

/* GET admin-login */
router.get('/admin', async (req, res) => {
    const locals = {
        title: "Admin",
        description: "Simple Blog"
    };
    try {
        res.render('admin/index', { locals, layout: adminLayout });
    } catch (error) {
        console.error("Error rendering admin login:", error);
        res.status(500).send("Server Error");
    }
});

/* POST admin-check login */
router.post('/admin', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id }, jwtSecret);
        res.cookie('token', token, { httpOnly: true });
        res.redirect('/dashboard');
    } catch (error) {
        console.error("Error during admin login:", error);
        res.status(500).json({ message: 'Server Error' });
    }
});

/* GET admin dashboard */
router.get('/dashboard', authMiddleware, async (req, res) => {
    try {
        const locals = {
            title: 'Dashboard',
            description: 'Simple Blog created with Node.js'
        };
        const data = await Post.find();
        res.render('admin/dashboard', {
            locals,
            data,
            layout: adminLayout
        });
    } catch (error) {
        console.error("Error loading dashboard:", error);
        res.status(500).send("Server Error");
    }
});

/* GET admin add new post */
router.get('/add-post', authMiddleware, async (req, res) => {
    try {
        const locals = {
            title: 'Add Post',
            description: 'Simple Blog created with Node.js'
        };
        res.render('admin/add-post', {
            locals,
            layout: adminLayout
        });
    } catch (error) {
        console.error("Error loading add post page:", error);
        res.status(500).send("Server Error");
    }
});

/* POST admin create new post */
router.post('/add-post', authMiddleware, async (req, res) => {
    try {
        const { title, body } = req.body;
        await Post.create({ title, body });
        res.redirect('/dashboard');
    } catch (error) {
        console.error("Error adding post:", error);
        res.status(500).send("Server Error");
    }
});

/* GET admin edit post */
router.get('/edit-post/:id', authMiddleware, async (req, res) => {
    try {
        const locals = {
            title: 'Edit Post',
            description: 'Simple Blog created with Node.js'
        };
        const data = await Post.findById(req.params.id);
        res.render('admin/edit-post', {
            locals,
            data,
            layout: adminLayout
        });
    } catch (error) {
        console.error("Error loading edit post page:", error);
        res.status(500).send("Server Error");
    }
});

/* PUT admin update post */
router.put('/edit-post/:id', authMiddleware, async (req, res) => {
    try {
        await Post.findByIdAndUpdate(req.params.id, {
            title: req.body.title,
            body: req.body.body,
            updatedAt: Date.now()
        });
        res.redirect('/dashboard');
    } catch (error) {
        console.error("Error updating post:", error);
        res.status(500).send("Server Error");
    }
});

/* DELETE post by ID */
router.delete('/delete-post/:id', authMiddleware, async (req, res) => {
    try {
        console.log(`Attempting to delete post with ID: ${req.params.id}`);  // ✅ Debug log

        const post = await Post.findByIdAndDelete(req.params.id);

        if (!post) {
            console.error(`Post not found with ID: ${req.params.id}`);
            return res.status(404).send("Post not found");
        }

        console.log(`Successfully deleted post with ID: ${req.params.id}`);
        res.redirect('/dashboard');
    } catch (error) {
        console.error("Error deleting post:", error);
        res.status(500).send("Server Error");
    }
});



/* POST admin-register */
router.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(409).json({ message: 'Username already in use' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await User.create({ username, password: hashedPassword });
        res.status(201).json({ message: 'User created successfully', user });
    } catch (error) {
        console.error("Error during user registration:", error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

module.exports = router;