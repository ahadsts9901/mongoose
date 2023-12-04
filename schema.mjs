import mongoose from "mongoose";

export const emailPattern = /^[a-zA-Z0-9!#$%&'*+-/=?^_`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/; // RFC 822 email specification
export const passwordPattern = /^(?=.*[a-zA-Z])(?=.*\d)[a-zA-Z\d]{6,100}$/;
export const otpPattern = /^[0-9]{6}$/;
export const profilePicturePattern = /^https:\/\/[^\s\/$.?#].[^\s]*$/;
export const firstNamePattern = /^[a-zA-Z0-9 !@#$%^&*()_+{}\[\]:;<>,.?~\\/-]{2,15}$/;
export const lastNamePattern = /^[a-zA-Z0-9 !@#$%^&*()_+{}\[\]:;<>,.?~\\/-]{2,15}$/;
export const otpMaxAgeInMinutes = 15;
export const forgetPasswordOtpMaxAgeInMinutes = 15;
export const initialSessionInDays = 15;
export const extendedSessionInDays = 30;

// mongoose schemas

// user schema
// ==================================================================================================

let userSchema = new mongoose.Schema({
    profilePhoto: {
        type: String,
        default: null,
        maxlength: 1000,
        match: profilePicturePattern
    },
    firstName: {
        type: String,
        required: [true, 'first name is required'],
        minlength: 2,
        maxlength: 15,
        trim: true,
    },
    lastName: {
        type: String,
        required: [true, 'last name is required'],
        minlength: 2,
        maxlength: 15,
        trim: true,
    },
    email: {
        type: String,
        unique: true,
        required: [true],
        minlength: 3,
        maxlength: 100,
        trim: true,
        match: emailPattern
    },
    password: {
        type: String,
        required: [true, 'password is required'],
        // minlength: 6,
        // maxlength: 100,
        // match: passwordPattern // this field gonna be bcrypt hash
    },
    isSuspended: {
        type: Boolean,
        default: false
    },
    isDisabled: {
        type: Boolean,
        default: false
    },
    isEmailVerified: {
        type: Boolean,
        default: false
    },
    isAdmin: {
        type: Boolean,
        default: false
    },
    createdOn: {
        type: Date,
        default: Date.now
    }
});

userSchema.pre('save', function (next) {
    // Convert the email to lowercase before saving
    if (this.email) {
        this.email = this.email.toLowerCase();
    }
    next();
});


export const userModel = mongoose.model("users", userSchema);

export const sampleUser = `{
    "firstName": "John", 
    "lastName": "Doe", 
    "email": "john@example.com",
    "password": "s4e5br2th4j242342h342b4vhv...werwdf32",
    "isAdmin": false,
    "isDisabled": false,
    "isSuspended": false,
    "isEmailVerified": false,
    "profilePhoto": "https://example.com/profile.jpg"
    "createdOn": "2022-01-01T00:00:00.000Z"
}`

// email otp schema
// ==================================================================================================

let otpSchemaEmail = new mongoose.Schema({
    email: {
        type: String,
        unique: false,
        required: [true],
        minlength: 3,
        maxlength: 100,
        trim: true,
        match: emailPattern
    },
    otpCodeHash: {
        type: String,
        required: [true, 'otpHash is required'],
        // minlength: 6,
        // maxlength: 6,
        // match: otpPattern // this field gonna be bcrypt hash
    },
    isUsed: {
        type: Boolean,
        default: false
    },
    createdOn: {
        type: Date,
        default: Date.now
    }
});

otpSchemaEmail.pre('save', function (next) {
    // Convert the email to lowercase before saving
    if (this.email) {
        this.email = this.email.toLowerCase();
    }
    next();
});


export const otpModelEmail = mongoose.model("email-otps", otpSchemaEmail);

export const sampleOtpemail = `{
    "email": "john@example.com",
    "otpHash": "s4e5br2th4j242342h342b4vhv...werwdf32",
    "isUsed": false,
    "createdOn": "2022-01-01T00:00:00.000Z"
}`

// password otp schema
// ==================================================================================================

let otpSchemaPassword  = new mongoose.Schema({
    email: {
        type: String,
        required: [true],
        minlength: 3,
        maxlength: 100,
        trim: true,
        match: emailPattern,
        unique: true
    },
    otpCodeHash: {
        type: String,
        required: [true, 'otpHash is required'],
        // minlength: 6,
        // maxlength: 6,
        // match: otpPattern // this field gonna be bcrypt hash
    },
    isUsed: {
        type: Boolean,
        default: false
    },
    createdOn: {
        type: Date,
        default: Date.now
    }
});

otpSchemaPassword.pre('save', function (next) {
    // Convert the email to lowercase before saving
    if (this.email) {
        this.email = this.email.toLowerCase();
    }
    next();
});

export const otpModelPassword = mongoose.model("password-otps", otpSchemaPassword);

export const sampleOtpPassword = `{
    "email": "john@example.com",
    "otpHash": "s4e5br2th4j242342h342b4vhv...werwdf32",
    "isUsed": false,
    "createdOn": "2022-01-01T00:00:00.000Z"
}`