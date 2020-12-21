const express = require("express");
const bcrypt = require("bcrypt")
const MongoClient = require("mongodb").MongoClient;
const ObjectId = require("mongodb").ObjectID;
const jwt = require("jsonwebtoken")

const app = express();
const jsonParser = express.json();

const mongoClient = new MongoClient("mongodb://localhost:27017/", { useNewUrlParser: true });
const SECRET_KEY = 'RANDOM_SECRET'

let dbClient;

const withAuthorization = (callback) => (request, response) => {
    const collection = request.app.locals.collection
    const userId = request.headers[ 'user-id' ]
    const token = request.headers.token

    if (!userId || !token)
        return response.status(401).json({ error: 'Отказано в доступе' })

    collection.findOne({ _id: ObjectId(userId), token }).then(user => {
        if (!user) {
            return response.status(401).json({ error: 'Отказано в доступе' })
        }

        callback(request, response)
    })
}

mongoClient.connect(function(err, client){
    if(err) return console.log(err);
    dbClient = client;
    app.locals.collection = client.db("usersdb").collection("users");
    app.locals.collectionPlanet = client.db("usersdb").collection("planets")
    app.listen(8000, function(){
        console.log("Сервер ожидает подключения...");
    });
});

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content, Accept, Content-Type, Authorization, user-id, token');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    next();
});

app.use((req, res, next) => {
    console.log('Запрос', req.originalUrl)
    next()
})

app.post("/api/login", jsonParser, function(request, response){
    const collection = request.app.locals.collection

    collection.findOne({ username: request.body.username }).then(user => {
        if (!user) {
            return response.status(401).json({ error: 'Такого пользователя не существует' })
        }
        bcrypt.compare(request.body.password, user.password).then(valid => {
            if (!valid) {
                return response.status(401).json({
                    error: 'Неверный пароль'
                })
            }

            const token = jwt.sign(
                { username: request.body.username },
                SECRET_KEY,
                { expiresIn: '24h' }
            )
            collection.updateOne({ _id: user._id }, { $set: { token } }).then(() =>
                response.status(200).json({
                    userId: user._id,
                    token: token,
                })).catch(
                (error) => {
                    response.status(500).json({
                        error: error
                    })
                }
            )
        }).catch(
            (error) => {
                response.status(500).json({
                    error: error
                })
            }
        )
    }).catch(
        (error) => {
            response.status(500).json({
                error: error
            })
        }
    )
})

app.post('/api/register', jsonParser, (request, response) => {
    const user = {
        email: request.body.email,
        username: request.body.username,
        password: request.body.password
    }

    const collection = request.app.locals.collection
    collection.find({ username: user.username }).count((err, count) => {
        if (err) {
            console.log(err)
            return
        }

        if (count !== 0) {
            response.send({ error: 'Пользователь с таким именем пользователя уже существует.' })
            return
        }

        collection.find({ email: user.email }).count((err, count) => {
            if (err) {
                console.log(err)
                return
            }

            if (count !== 0) {
                response.send({ error: 'Пользователь с таким email уже существует.' })
                return
            }

            console.log('Добавление нового пользователя: ', user)
            bcrypt.hash(user.password, 10).then(
                hash => {
                    user.password = hash
                    user.token = jwt.sign(
                        { username: user.username },
                        SECRET_KEY,
                        { expiresIn: '24h' }
                    )
                    collection.insertOne(user, (err, res) => {
                        if (err) {
                            console.log(err)
                            response.status(500).json({ error: err })
                            return
                        }

                        response.status(200).json({ token: user.token, userId: res.insertedId })
                    })
                }
            )
        })
    })
})

app.get('/api/planetList', jsonParser, withAuthorization((request, response) => {
    const collection = request.app.locals.collectionPlanet
    collection.find({}).toArray((err, planets) => {
        if (err) {
            response.status(500).json({
                error: err
            })
            return
        }

        response.send(planets)
    })
}))

app.post('/api/addPlanet', jsonParser, withAuthorization((request, response) => {
    const collection = request.app.locals.collectionPlanet

    const planet = {
        name: request.body.name,
        weight: request.body.weight
    }

    collection.insertOne(planet, (err) => {
        if (err) {
            response.status(500).json({
                error: err
            })
        }

        response.send({})
    })
}))

process.on("SIGINT", () => {
    dbClient.close();
    process.exit();
});