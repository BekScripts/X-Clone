import User from "../models/user.models.js"
import bcrypt from "bcryptjs";
import { generateTokenAndSetCookie } from "../lib/generateTokens.js";


/**----------------------------------  Signup ----------------------------------------- */
export const signup = async (req, res) => {
    try {
        const { fullname, username, email, password } = req.body;
        const emailRegex = /^\S+@\S+\.\S+$/;

        if (!fullname || !username || !email || !password) {
            return res.status(400).json({ error: "All fields are required" });
        }

        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: "Invalid email format" });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).json({ error: "Username is already taken" });
        }

        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(400).json({ error: "Email is already taken" });
        }

        if (password.length < 6) {
            return res.status(400).json({
                error: "Password must be at least 6 characters long"
            })
        }

        // Hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Create and save the new user
        const newUser = new User({
            fullname,
            username,
            email,
            password: hashedPassword
        });
        await newUser.save();

        // Generate token and set cookie
        generateTokenAndSetCookie(newUser._id, res);

        res.status(201).json({
            _id: newUser._id,
            fullname: newUser.fullname,
            username: newUser.username,
            email: newUser.email,
            followers: newUser.followers,
            following: newUser.following,
            profileImg: newUser.profileImg,
            coverImg: newUser.coverImg
        });
    } catch (error) {
        console.error("Error in signup controller:", error.message);
        res.status(500).json({ error: "Internal Server Error" });
    }
};


/**----------------------------------  Login ----------------------------------------- */
export const login = async (req, res) => {
    try {
        console.log(req.body);
        const {username, password } = req.body;

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({
                error: "Invalid username "+ username +" "+password
            })
        }

        if (!(await bcrypt.compare(password, user.password))) {
            return res.status(400).json({
                error: "Invalid password",
            });
        }

        generateTokenAndSetCookie(user._id, res);

        res.status(201).json({
            _id: user._id,
            fullname: user.fullname,
            username: user.username,
            email: user.email,
            followers: user.followers,
            following: user.following,
            profileImg: user.profileImg,
            coverImg: user.coverImg
        });

    }
    catch (error) {
        console.error("Error in login controller: ", error.message);
        res.status(500).json({
            error: "Internal Server Error"
        })
    }
}

/**----------------------------------  Logout ----------------------------------------- */
export const logout = async (req, res) => {
    try {
        res.cookie("jwt", "", { maxAge: 0 })
        res.status(200).json({ message: "Logged out successfully" });

    } catch (error) {
        console.error("Error in the Logout controller: ", error);
        res.status(500).json({
            error: "Internal Server Error"
        })
    }
}

/**----------------------------------  getMe ----------------------------------------- */

export const getMe = async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select("-password");
        res.status(200).json(user);
    }
    catch (error) {
        console.log("Error in the getMe controller", error.message);
        res.status(500).json({
            error: "Internal Server Error"
        });
    }
}