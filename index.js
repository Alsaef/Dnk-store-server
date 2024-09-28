const express = require('express')
const cors = require('cors')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
require('dotenv').config()
const app = express()
const port = 5000 || process.env.PORT

app.use(express.json());
app.use(cors())


const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const uri = `mongodb+srv://${process.env.DB}:${process.env.password}@cluster0.hwuf8vx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});



const verifyJWT = (req, res, next) => {
  //  console.log(req.headers.authorize)
  const authorize = req.headers.authorize;
  if (!authorize) {
    return res.status(401).send({ error: true, message: 'unauthorize access' })
  }
  const token = authorize.split(' ')[1]
  console.log(token)
  jwt.verify(token, process.env.SecretToken, (error, decoded) => {
    if (error) {
      return res.status(401).send({ error: true, message: "unauthorize access" })
    }
    req.decoded = decoded
    next()
  })
}



async function run() {
  try {



    const database = client.db('DNK-ADVANCE-DB')
    const usersCollection = database.collection("users");
    const productCollection = database.collection("products");
    const orderCollection = database.collection("orders");


    app.post('/api/v1/register', async (req, res) => {
      const { name, email, photo, password, role } = req.body
      const existing = await usersCollection.findOne({ email: email })
      if (existing) {
        return res.status(401).send({ message: 'user exist' });
      }

      const hashPassword = await bcrypt.hash(password, 10)
      const user = {
        name: name,
        email: email,
        password: hashPassword,
        photo: photo,
        role: role
      }
      await usersCollection.insertOne(user);
      res.status(200).send({
        status: true
      })
    })


    app.post("/api/v1/login", async (req, res) => {
      const { email, password } = req.body;

      const user = await usersCollection.findOne({ email: email });

      if (!user) {
        return res.status(401).json({ message: "Invalid email" });
      }

      const isPassword = await bcrypt.compare(password, user.password);
      if (!isPassword) {
        return res.status(401).json({ message: "Invalid password" });
      }
      const token = jwt.sign(
        { id: user._id, role: user.role, name: user.name, email: user.email, photo: user.photo },
        process.env.SecretToken,
        { expiresIn: '100d' }
      );

      res.json({ status: true, token });
    });

    app.get('/api/v1/products', async (req, res) => {
      const result = await productCollection.find().toArray();
      res.status(200).send(result)
    })
    app.get('/api/v1/products/search', async (req, res) => {
      const { searchQuery } = req.query
      const filter = {
        $or: [
          { name: { $regex: searchQuery, $options: 'i' } },
          { category: { $regex: searchQuery, $options: 'i' } },
          { location: { $regex: searchQuery, $options: 'i' } },
        ]
      }

      if (searchQuery) {
        const product = await productCollection.find(filter).toArray();
        return res.status(200).json(product);
      }
    })
    app.post('/api/v1/products', async (req, res) => {
      const createProducts = req.body;
      const result = await productCollection.insertOne(createProducts)
      res.status(200).send(result)
    })
    app.get('/api/v1/products/:id', async (req, res) => {
      const id = req.params.id
      const result = await productCollection.findOne({ _id: new ObjectId(id) });
      res.status(200).send(result)
    })


    // orders

    app.post('/api/v1/orders', async (req, res) => {
      const orderSub = req.body;
      await orderCollection.insertOne(orderSub)
      res.status(200).send({
        status: 'order successful submit'
      })
    })

    app.get('/api/v1/orders/:email',verifyJWT,async(req,res)=>{
      const email=req.params.email
      const result=await orderCollection.find({email:email}).sort({date:-1}).toArray()
      res.status(200).send(result)
    })
    app.delete('/api/v1/orders/:id',async(req,res)=>{
      const id=req.params.id
      const result=await orderCollection.deleteOne({_id:new ObjectId(id)})
      res.status(200).send(result)
    })

    // Connect the client to the server	(optional starting in v4.7)
    await client.connect();
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("Pinged your deployment. You successfully connected to MongoDB!");
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('Server Running!')
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})