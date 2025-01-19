import User from "../model/user.model.js";
import bcryptsjs from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from 'dotenv'
dotenv.config()
const secretKey=process.env.SECRET_KEY 
// Signup logic
export const signup = async (req, res) => {
  try {
    const { fullname, email, password,role } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: "User Already Exist" });
    }
    const hashPassword = await bcryptsjs.hash(password, 10);
    const createdUser = new User({
      fullname,
      email,
      role,
      password: hashPassword,
    });
    await createdUser.save();
    res.status(201).json({ message: "User Created Successfully" });
  } catch (error) {
    console.log("Error:" + error.message);
    res.status(500).json({ message: "Internal server error" });
  }
};

//Login Logic
// Login Logic
export const login = async (req, res) => {
 
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    
    // Check if user exists
    if (!user) {
      return res.status(400).json({ message: "Invalid Credentials" });
    }
    
    // Check if password matches
    const isMatch = await bcryptsjs.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid Credentials" });
    }
    
    // Create and sign token
    jwt.sign({ id: user._id, email: user.email, role: user.role }, secretKey, { expiresIn: '7d' }, (err, token) => {
      if (err) {
        console.log('Token generation error:', err.message);
        return res.status(500).json({ message: "Error generating token" });
      }
      res.status(200).json({ message: 'Login Successful', token });
    });

};

export const me = async (req, resp) => {
  jwt.verify(req.token, secretKey, async (err, authData) => {
    if (err) {
      console.log('Token verification error:', err.message);
      return resp.status(400).json({ message: 'Invalid token' });
    } else {
    
        // Retrieve user from the database
        const user = await User.findById(authData.id);
        if (!user) {
          return resp.status(404).json({ message: 'User not found' });
        }
        // Respond with user data
        resp.json({ user: { fullname: user.fullname, email: user.email, role: user.role ,id:user._id} });
      
    }
  });
};


