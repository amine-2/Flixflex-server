const port = 8000;
const express = require('express')
const { MongoClient } = require('mongodb')
const { v1: uuidv1 } = require('uuid')
const jwt= require('jsonwebtoken')
const cors = require('cors')
const bcrypt= require('bcrypt')
const { query } = require('express')
require('dotenv').config()

const uri = process.env.URI

const app = express()
app.use(cors())
app.use(express.json())



app.post('/signup', async (req, res) => {
    const client = new MongoClient(uri)
    const { userName, password } = req.body
    console.log(req.body)

    const generateUserId = uuidv1()
    const hashedPassword = await bcrypt.hash(password, 10)
    
    
    try {
        await client.connect()
        const database = client.db('FlixFlex')
        const users = database.collection('users')
        const exsistingUser = await users.findOne({ userName })
        
        if (exsistingUser) {
            return  res.status(409).send('user already exists please login')
        }
        const sanitizeduserName = userName.toLowerCase()
        
        const data = {
            user_id: generateUserId,
            userName: sanitizeduserName,
            hashed_password: hashedPassword
        }
        console.log(data)
        
        const insertedUser = await users.insertOne(data)
        const token = jwt.sign( insertedUser, sanitizeduserName, {
            expiresIn: 60 * 20
        })

        res.status(201).json({ token, userId: generateUserId })


    } catch(err) {
        console.log(err)
    }finally{
        await client.close()
    }
})


app.post ('/login', async (req, res) => { 
    const client = new MongoClient(uri)
    const { userName, password}= req.body
    
    try{
        await client.connect()
        const database = client.db('FlixFlex')
        const users = database.collection('users')

        const user = await users.findOne({ userName })
        const correctPassword = await bcrypt.compare(password , user.hashed_password)

        if (user && correctPassword) {

            const token= jwt.sign(user ,userName, {
                expiresIn : 60*24
            })

          res.status(201).json({token , userId: user.user_id})  

        }else
       { res.status(400).send('Invalide Credentials')}

        
    }catch(err){
        console.log(err)
    }finally{
        await client.close()
    }
    
})


app.listen(port,()=>console.log('server runing on port :' + port))