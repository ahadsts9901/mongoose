import jwt from 'jsonwebtoken';
import "dotenv/config"
import { extendedSessionInDays, initialSessionInDays } from './schema.mjs';
import { errorCodes } from './core.mjs';

// generate harts middleware

export const issueLoginToken = (req, res, next) => {

    const { isAdmin, firstName, lastName, email, _id, profilePhoto} = req.user;

    // hartRef

    const hartRef = jwt.sign({
        isAdmin: isAdmin,
        firstName: firstName,
        lastName: lastName,
        email: email,
        _id: _id,
        profilePhoto: profilePhoto,
    }, process.env.SECRET, {
        expiresIn: `${extendedSessionInDays}d`
    });

    res.cookie('hartRef', hartRef, {
        httpOnly: true,
        secure: true,
        expires: new Date(Date.now() + extendedSessionInDays * 24 * 60 * 60 * 1000)
    });

    // hart

    const hart = jwt.sign({
        isAdmin: isAdmin,
        firstName: firstName,
        lastName: lastName,
        email: email,
        _id: _id,
        profilePhoto: profilePhoto,
    }, process.env.SECRET, {
        expiresIn: `${initialSessionInDays}d`
    });

    res.cookie('hart', hart, {
        httpOnly: true,
        secure: true,
        expires: new Date(Date.now() + initialSessionInDays * 24 * 60 * 60 * 1000)
    });

    next()

}