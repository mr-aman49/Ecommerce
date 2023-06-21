import { compare } from "bcrypt";
import userModel from "../models/userModel.js";
import { comparePassword, hashPassword } from './../helpers/authHelper.js';
import  JWT from "jsonwebtoken";

export const registerController = async(req,res) =>{
    try{
        const{name,email,password,phone,address} =req.body
        // console.log(name,password)
        // validations
        if(!name){
            return res.send({error:'Name is Required'})
        }
        if(!email){
            return res.send({error:'Email is Required'})
        }
        if(!password){
            return res.send({error:'Password is Required'})
        }
        if(!phone){
            return res.send({error:'Phone no. is Required'})
        }
        if(!address){
            return res.send({error:'Address is Required'})
        }

        //check user
        const existinguser =await userModel.findOne({email})
        //exiting user
        if(existinguser){
            return res.status(200).send({
                success:true,
                message:'Already registered plaese login',
            })

        }
        //register user
        const hashedPassword =await hashPassword(password)
        // save
        const user = await new userModel({
            name,
            email,
            phone,
            address,
            password:hashedPassword,
        }).save();

        res.status(201).send({
            success:true,
            message:'User Register sucessfully',
            user
        })
    }catch(error){
        console.log(error)
        res.status(500).send({
            success:false,
            message:'Error in Registration',
            error
        })
    }
};

//POST LOGIN
export const loginController = async(req,res) => {
    try{
        const {email,password} = req.body
        //validatiom
        if(!email || !password){
            return res.status(404).send({
                success: false,
                message:"Invalid email or password"
            })
        }
        //checkuser
        const user = await userModel.findOne({email})
        if(!user){
            return res.status(404).send({
                success: false,
                message:"Email is not registerd"
            })
        }
        const match = await comparePassword(password,user.password)
        if (!match ){
            return  res.status(200).send({
                success : false,
                message :"Incorrect Password",
                })
            }

            //token
            const token = await JWT.sign({_id:user._id},process.env.JWT_SECRET, {
                expiresIn: "7d",
            });
            res.status(200).send({
                success:true,
                message:'login successfully',
                user:{
                    name:user.name,
                    email:user.email,
                    phone:user.phone,
                    address:user.address,

                },
                token,
            })
    }catch (error){
        console.log(error)
        res.status(500).send({
            success:false,
            message:'Error In Login',
            error
        })
    }
};

//test controller
export const testController = (req,res) =>{
    res.send('Protected Routes');
};
