import express from 'express';
// import path from 'path';
import jwt from 'jsonwebtoken';
import 'dotenv/config'
// const __dirname = path.resolve();
import cors from 'cors';
import morgan from 'morgan';
import "./mongodb.mjs"

import { userModel, sampleUser } from './schema.mjs';

import unAuthenticatedAuthRouter from './routes/un-auth-routes/auth.mjs'
import authenticatedAuthRouter from './routes/auth-routes/auth.mjs'
import cookieParser from 'cookie-parser'
import { errorCodes } from './core.mjs';
// import { decode } from 'punycode';

const app = express();
app.use(express.json()); // body parser
app.use(cookieParser()); // cookie parser
app.use(
    cors({
        origin: 'http://localhost:3000', // allow to server to accept request from different origin
        credentials: true,
    })
);

// un authenticated routes goes here
app.use("/api/v1", unAuthenticatedAuthRouter)

// authenticated routes goes here
// app.use("/api/v1", authenticatedAuthRouter)

app.use("/api/v1", (req, res, next) => {

    const hart = req.cookies.hart;

    try {
        const currentUser = jwt.verify(hart, process.env.SECRET);

        req.currentUser = {
            ...currentUser
        };

        next();

    } catch (err) {
        console.error(err);
        res.status(401).send({
            message: "unauthorized",
            errorCode: errorCodes.UNAUTHORIZED
        });
        return;
    }
});

// app.use(express.static(path.join(__dirname, 'web/build')))
// app.get(express.static(path.join(__dirname, 'web/build')))
// app.use("*", express.static(path.join(__dirname, 'web/build')))

// auth roures goes there
app.use("/api/v1", authenticatedAuthRouter)

app.get("/api/v1/is-login", (req, res) => {
    res.status(200).send({ message: "OK" });
})

const PORT = process.env.PORT || 5002;
app.listen(PORT, () => {
    console.log(`Example server listening on port ${PORT}`)
})