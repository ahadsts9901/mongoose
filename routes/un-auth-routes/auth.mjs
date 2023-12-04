import express from 'express';
import { stringToHash, varifyHash } from "bcrypt-inzi";
import otpGenerator from 'otp-generator';
import moment from "moment"

import {
    emailPattern, passwordPattern, firstNamePattern, lastNamePattern,
    otpPattern, profilePicturePattern, otpMaxAgeInMinutes, forgetPasswordOtpMaxAgeInMinutes,
    initialSessionInDays, extendedSessionInDays, userModel, otpModelEmail, otpModelPassword
}
    from '../../schema.mjs';
import { errorCodes } from '../../core.mjs'
import { sendEmail } from '../../functions.mjs';
import { issueLoginToken } from '../../middlewares.mjs';
import "dotenv/config"

let router = express.Router()

// signup api

router.post('/signup', async (req, res, next) => {

    try {

        // if parameters are not provided
        if (
            !req.body?.firstName
            || !req.body?.lastName
            || !req.body?.email
            || !req.body?.password
        ) {
            res.status(403).send({
                errorCode: errorCodes.REQUIRED_PARAMETER_MISSING,
                message: `required parameters missing, 
                    example request body:
                    {
                        firstName: "John",
                        lastName: "Doe",
                        email: "john@example.com"
                        password: "password123",
                    }
                    Password rules: 
                        1) length must between 6 to 20.
                        2) at least one alphabet (a to z or A to Z).
                        3) at least one digit (0-9).
                    `});
            return;
        }

        if (!firstNamePattern.test(req.body.firstName)) {
            res.status(403).send({
                errorCode: errorCodes.INVALID_FIRST_NAME,
                message: "invalid first name pattern"
            })
            return;
        }

        if (!lastNamePattern.test(req.body.lastName)) {
            res.status(403).send({
                errorCode: errorCodes.INVALID_LAST_NAME,
                message: "invalid last name pattern"
            })
            return;
        }

        if (!emailPattern.test(req.body.email)) {
            res.status(403).send({
                errorCode: errorCodes.INVALID_EMAIL,
                message: "invalid email"
            })
            return;
        }

        if (!passwordPattern.test(req.body.password)) {
            res.status(403).send({
                errorCode: errorCodes.INVALID_PASSWORD,
                message: "password must be between 6 to 20 characters and contain at least one alphabet and one number"
            })
            return;
        }

        const user = await userModel.findOne({ email: req.body.email }).exec();

        if (user) {
            res.status(409).send({
                message: "user already exists",
                errorCode: errorCodes.USER_ALREADY_EXIST
            });
            return;
        }

        // create a user

        const passwordHash = await stringToHash(req.body.password);

        const userAccountResponse = await userModel.create({
            firstName: req.body.firstName,
            lastName: req.body.lastName,
            email: req.body.email,
            password: passwordHash,
            profilePhoto: null,
        });

        res.send({
            message: "user created successfully proceed to email verification",
            errorCode: errorCodes.SUCCESS
        })

    } catch (error) {
        console.error(error);
        res.status(500).send({
            message: 'server error, please try later',
            errorCode: errorCodes.UNKNOWN_SERVER_ERROR
        });
    }
});

// send otp
router.post(`/send-otp-email`, async (req, res, next) => {

    // step 1: validations of email

    // parameters validation
    if (!req.body.email) {
        res.status(403).send({
            message: `required parameters missing, example request body: { "email": "john@example.com" }`,
            errorCode: errorCodes.REQUIRED_PARAMETER_MISSING
        });
        return;
    }

    // email pattern
    if (!emailPattern.test(req.body.email)) {
        res.status(403).send({
            message: `invalid email, example request body: { "email": "john@example.com" }`,
            errorCode: errorCodes.INVALID_EMAIL
        });
        return;
    }

    // get user
    const user = await userModel.findOne({ email: req.body.email }).exec();

    // check time of otp

    // step 2: check if user not exist
    if (!user) {
        res.status(404).send({
            message: `user not exist`,
            errorCode: errorCodes.USER_NOT_EXIST
        });
        return;
    }

    // step 3: check if email is already verified
    if (user.isEmailVerified) {
        res.status(409).send({
            message: `email is already verified, please login`,
            errorCode: errorCodes.EMAIL_ALREADY_VERIFIED
        });
        return;
    }


    // get otp for opt time based throttling
    const otp = await otpModelEmail
        .find({
            email: req.body.email,
            createdOn: {
                // getting otp that is created within last 24hr
                $gte: moment().subtract(24, 'hours').toDate()
            }
        })
        .sort({ _id: -1 })
        .limit(3)
        .exec();

    // time based throttling criteria
    // 1st OTP: No delay.
    // 2nd OTP: 5 minutes delay.
    // 3rd OTP: 1 hour delay.
    // 4th OTP: 24 hours delay.

    if (otp?.length >= 3) {// if three otp created within 24hr

        res.status(429).send({
            message: `limit exceed, please try again in 24hr`,
            errorCode: errorCodes.LIMIT_EXCEED_TRY_IN_24HR
        });
        return;

    } else if (otp?.length === 2) { // if two otp created within 24hr

        // it should be older than 60 minutes
        if (moment().diff(moment(otp[0].createdOn), 'minutes') <= 60) {
            res.status(429).send({
                message: `limit exceed, wait 60 minutes before sending another OTP`,
                errorCode: errorCodes.LIMIT_EXCEED_TRY_IN_60MIN
            });
            return;
        }

    } else if (otp?.length === 1) { // if only one otp created within 24hr

        // it should be older than 5 minutes
        if (moment().diff(moment(otp[0].createdOn), 'minutes') <= 5) {
            res.status(429).send({
                message: `limit exceed, wait 5 minutes before sending another OTP`,
                errorCode: errorCodes.LIMIT_EXCEED_TRY_IN_5MIN
            });
            return;
        }

    }

    // generate OTP code
    const otpCode = otpGenerator.generate(6, {
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false
    });

    const otpCodeHash = await stringToHash(otpCode);

    // save OTP code to database
    const insertResponse = await otpModelEmail.create({
        email: req.body.email,
        otpCodeHash: otpCodeHash,
    });

    // send OTP code
    // nodemailer

    try {
        // Send verification email
        await sendEmail(
            user.email,
            user.firstName,
            `Hi ${user.firstName}! Verify your email`,
            `Hi ${user.firstName}! Here is your email verification OTP code. This is valid for 15 minutes: ${otpCode}`
        );

        // Response after successfully sending email
        res.send({
            message: 'verification email has been sent',
            errorCode: errorCodes.SUCCESS
        });

    } catch (error) {
        // Handle error from sendEmail
        console.error(error);
        res.status(500).send({
            message: 'Error sending email',
            errorCode: errorCodes.UNKNOWN_SERVER_ERROR
        });
        return;
    }
})

// verify email api

router.post('/verify-email', async (req, res, next) => {

    // parameters validation
    if (!req.body.email ||
        !req.body.otpCode
    ) {
        res.status(403).send({
            message: `required parameters missing, example request body:
        {
            "email": "john@example.com",
            "otpCode": "XXXXXX"
        }`
        });
        return;
    }

    req.body.email = req.body.email.toLowerCase();

    if (!emailPattern.test(req.body.email)) {
        res.status(403).send({
            message: "invalid email",
            errorCode: errorCodes.INVALID_EMAIL
        });
        return;
    }

    if (!otpPattern.test(req.body.otpCode)) {
        res.status(403).send({
            message: "invalid otp",
            errorCode: errorCodes.INVALID_OTP
        });
        return;
    }

    try {
        let result = await otpModelEmail.findOne({ email: req.body.email }).sort({ _id: -1 }).exec();

        if (!result) { // user not found
            res.status(403).send({
                message: "invalid otp",
                errorCodes: errorCodes.INVALID_OTP
            })
            return;
        }

        // check if OTP code is valid
        const isValid = await varifyHash(req.body.otpCode, result.otpCodeHash);

        if (!isValid) { // OTP code is not valid
            res.status(403).send({
                message: "invalid otp",
                errorCode: errorCodes.INVALID_OTP
            })
            return;
        }

        // check if OTP code is expired
        const isExpired = moment().isAfter(moment(result.createdOn).add(15, 'minutes'));

        if (isExpired) { // OTP code is expired
            res.status(403).send({
                message: "invalid otp",
                errorCode: errorCodes.INVALID_OTP
            })
            return;
        }

        if (result.isUsed) {
            res.status(403).send({
                message: "invalid otp",
                errorCode: errorCodes.INVALID_OTP
            })
            return;
        }

        // update OTP code in database
        const updateOtpResponse = await otpModelEmail.updateOne({ email: req.body.email }, { $set: { isUsed: true } });

        // update user account
        const updateResponse = await userModel.updateOne({ email: req.body.email }, { $set: { isEmailVerified: true } });

        // find user in database
        const userAccountResponse = await userModel.findOne({ email: req.body.email }).exec();

        res.send({
            message: "email verified succesfully",
            errorCode: errorCodes.SUCCESS
        });

    } catch (error) {
        console.error(error);
        res.status(500).send({
            message: 'server error, please try later',
            errorCode: errorCodes.UNKNOWN_SERVER_ERROR
        });
    }
})

// login api

router.post('/login', async (req, res, next) => {

    // parameters validation
    if (!req.body.email ||
        !req.body.password
    ) {
        res.status(403);
        res.send({
            message: `required parameters missing, 
        example request body:
        {
            email: "john@example.com",
            password: "XXXXXXXX",
        } `,
            errorCode: errorCodes.REQUIRED_PARAMETER_MISSING
        });
        return;
    }

    req.body.email = req.body.email.toLowerCase();

    // check email pattern
    if (!emailPattern.test(req.body.email)) {
        res.status(403).send({
            errorCode: errorCodes.INVALID_EMAIL,
            message: "invalid email"
        })
        return;
    }

    // check password pattern
    if (!passwordPattern.test(req.body.password)) {
        res.status(403).send({
            errorCode: errorCodes.INVALID_PASSWORD,
            message: "password must be between 6 to 20 characters and contain at least one alphabet and one number"
        })
        return;
    }

    try {
        const result = await userModel.findOne({ email: req.body.email }).exec();

        if (!result) { // user not found
            res.status(400).send({
                message: "email or password incorrect",
                errorCode: errorCodes.INVALID_EMAIL_OR_PASSWORD
            });
            return;
        }

        // email not verified
        if (!result.isEmailVerified) {
            res.status(403).send({
                message: "email not verified",
                errorCode: errorCodes.EMAIL_NOT_VERIFIED
            });
            return;
        }

        // account disabled validation
        if (result.isDisabled) {
            res.status(400).send({
                message: "account is disabled",
                errorCode: errorCodes.ACCOUNT_DISABLED
            });
            return;
        }

        // account suspended validation
        if (result.isSuspended) {
            res.status(400).send({
                message: "account is suspended",
                errorCode: errorCodes.ACCOUNT_SUSPENDED
            });
            return;
        }

        const isMatch = await varifyHash(req.body.password, result.password)

        if (!isMatch) {

            res.status(401).send({
                message: "email or password incorrect",
                errorCode: errorCodes.INVALID_EMAIL_OR_PASSWORD
            })
            return;
        }

        // for next middleware

        req.user = {
            isAdmin: result.isAdmin,
            firstName: result.firstName,
            lastName: result.lastName,
            email: result.email,
            _id: result._id,
            profilePhoto: result.profilePhoto,
        };

        next();


    } catch (error) {
        console.error(error);
        res.status(500).send({
            message: 'server error, please try later',
            errorCode: errorCodes.UNKNOWN_SERVER_ERROR
        });
    }
},
    issueLoginToken,
    (req, res, next) => {
        res.send({
            message: "login successful",
            errorCode: errorCodes.SUCCESS,
        })
    }
)

// forget password api

router.post('/forget-password', async (req, res, next) => {

    // parameters validation
    if (!req.body.email) {
        res.status(403);
        res.send({
            message: `required parameters missing, example request body: { email: "john@example.com" }`,
            errorCode: errorCodes.REQUIRED_PARAMETER_MISSING,
        });
        return;
    }

    req.body.email = req.body.email.toLowerCase();

    // check email pattern
    if (!emailPattern.test(req.body.email)) {
        res.status(403).send({
            errorCode: errorCodes.INVALID_EMAIL,
            message: "invalid email"
        })
        return;
    }

    try {
        const user = await userModel.findOne({ email: req.body.email }).exec();

        if (!user) { // user not found
            res.status(404).send({
                message: "user not found",
                errorCode: errorCodes.USER_NOT_EXIST
            });
            return;
        }

        // account disabled validation
        if (user.isDisabled) {
            res.status(400).send({
                message: "account is disabled",
                errorCode: errorCodes.ACCOUNT_DISABLED
            });
            return;
        }

        // account suspended validation
        if (user.isSuspended) {
            res.status(400).send({
                message: "account is suspended",
                errorCode: errorCodes.ACCOUNT_SUSPENDED
            });
            return;
        }

        // generate otp code
        const otpCode = otpGenerator.generate(6, {
            upperCaseAlphabets: false,
            lowerCaseAlphabets: false,
            specialChars: false
        });

        const otpCodeHash = await stringToHash(otpCode);

        // save otp code to database
        const insertResponse = await otpModelPassword.create({
            email: req.body.email,
            otpCodeHash: otpCodeHash,
        });

        // send OTP code

        // nodemailer

        sendEmail(
            user.email,
            user.firstName,
            `Forget password OTP`,
            `Hi ${user.firstName}! Here is your forget password OTP code. This is valid for 15 minutes: ${otpCode}`
        )

        // send a response
        res.send({
            message: 'forget password otp code has sent',
            errorCode: errorCodes.SUCCESS,
        });

    } catch (error) {
        console.error(error);
        res.status(500).send({
            message: 'server error, please try later',
            errorCode: errorCodes.UNKNOWN_SERVER_ERROR
        });
    }
})

// forget password complete

router.post('/forget-password-complete', async (req, res, next) => {

    // parameters validation
    if (!req.body.email
        || !req.body.otpCode
        || !req.body.newPassword) {

        res.status(403);
        res.send(`required parameters missing, 
        example request body:
        {
            email: "john@example.com",
            otpCode: "XXXXXX",
            newPassword: XXXXXXXX,
        } `);
        return;
    }

    req.body.email = req.body.email.toLowerCase();

    // email pattern check
    if (!emailPattern.test(req.body.email)) {
        res.status(400).send({
            errorCode: errorCodes.INVALID_EMAIL,
            message: "invalid email"
        })
        return;
    }

    // password pattern check
    if (!passwordPattern.test(req.body.newPassword)) {
        res.status(400).send({
            errorCode: errorCodes.INVALID_PASSWORD,
            message: "password must be between 6 to 20 characters and contain at least one alphabet and one number"
        })
        return;
    }

    // otp pattern check
    if (!otpPattern.test(req.body.otpCode)) {
        res.status(400).send({
            errorCode: errorCodes.INVALID_OTP,
            message: "invalid otp"
        })
        return;
    }

    try {
        // find otp code hash in database
        const otpRecord = await otpModelPassword
            .findOne({ email: req.body.email })
            .sort({ _id: -1 })
            .exec();

        if (!otpRecord) { // otp not found
            res.status(403).send({
                message: "invalid otp",
                errorCode: errorCodes.INVALID_OTP
            });
            return;
        }

        // check if otp code is expired
        const isExpired = moment().isAfter(moment(otpRecord.createdOn).add(15, 'minutes'));

        if (isExpired) { // otp code is expired
            res.status(403).send({
                message: "invalid otp",
                errorCode: errorCodes.INVALID_OTP,
            })
            return;
        }

        // verify is otp used
        if (otpRecord.isUsed) {
            res.status(403).send({
                message: "invalid otp",
                errorCode: errorCodes.INVALID_OTP,
            });
            return;
        }

        // verify valid otp hash
        const isOtpValid = await varifyHash(req.body.otpCode, otpRecord.otpCodeHash);

        if (!isOtpValid) {
            res.status(403).send({
                message: "invalid otp",
                errorCode: errorCodes.INVALID_OTP,
            });
            return;
        }

        // make new password hash
        const passwordHash = await stringToHash(req.body.newPassword);


        // update new password
        const updateResp = await userModel.updateOne({
            email: otpRecord.email
        },
            {
                $set: { password: passwordHash }
            });

        otpRecord.isUsed = true;
        await otpRecord.save();

        // send a response
        res.send({
            message: 'forget password completed, proceed to login with new password',
            errorCode: errorCodes.SUCCESS,
        });

    } catch (error) {
        console.error(error);
        res.status(500).send({
            message: 'server error, please try later',
            errorCode: errorCodes.UNKNOWN_SERVER_ERROR
        });
    }
})


// social logins

// TODO

export default router