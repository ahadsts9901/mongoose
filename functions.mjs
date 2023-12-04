import nodemailer from 'nodemailer';
import { errorCodes } from './core.mjs';
import jwt from 'jsonwebtoken';
import "dotenv/config";

// send email
export const sendEmail = (email, firstName, subject, html) => {

    return new Promise(async (resolve, reject) => {
        try {
            const transporter = nodemailer.createTransport({
                host: 'smtp.gmail.com',
                port: 587,
                auth: {
                    user: process.env.NODE_MAILER_EMAIL,
                    pass: process.env.NODE_MAILER_PASSWORD
                }
            });

            const mail = await transporter.sendMail({
                from: '"Abdul Ahad" <ahad.btkit@gmail.com>',
                to: `${email}`,
                subject: subject,
                text: `Hello ${firstName}`,
                html: html,
            });

            await transporter.sendMail(mail);
            resolve(); // Resolve the Promise once the email is sent successfully
        } catch (error) {
            console.error(error);
            reject({
                message: 'Error sending email',
                errorCode: errorCodes.UNKNOWN_SERVER_ERROR
            });
        }
    });
};