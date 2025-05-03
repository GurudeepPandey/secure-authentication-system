import nodemailer from "nodemailer";
import Mailgen from "mailgen";


const sendMail = async (options) => {
    var mailGenerator = new Mailgen({
        theme: 'default',
        product: {
            name: 'Authentication System',
            link: 'https://secureauth.js/'
        }
    });

    var emailText = mailGenerator.generatePlaintext(options.mailGenContent);
    var emailHtml = mailGenerator.generate(options.mailGenContent);

    let transporter = nodemailer.createTransport({
        host: process.env.MAILTRAP_HOST,
        port: process.env.MAILTRAP_PORT,
        secure: false,
        auth: {
            user: process.env.MAILTRAP_USERNAME,
            pass: process.env.MAILTRAP_PASSWORD
        }
    });

    const mailbody = {
        from: process.env.MAILTRAP_SENDEREMAIL,
        to: options.email,
        subject: options.subject,
        text: emailText,
        html: emailHtml
    }

    try {
        await transporter.sendMail(mailbody)
    } catch (error) {
        console.log("Error while sending mail: ", error);
    }
}

const emailVerificationMail = (username, emailVerificationUrl) => {
    return {
        body: {
            name: username,
            intro: 'Welcome to Auth System! We\'re very excited to have you on board.',
            action: {
                instructions: 'To get started with Auth System, please click here:',
                button: {
                    color: '#22BC66', // Optional action button color
                    text: 'Verify your Email',
                    link: emailVerificationUrl
                }
            },
            outro: 'Need help, or have questions? Just reply to this email, we\'d love to help.'
        }
    }
};

const forgotPasswordMail = (username, resetPasswordUrl) => {
    return {
        body: {
            name: username,
            intro: 'We received a request to reset your password.',
            action: {
                instructions: 'To reset your password, please click here:',
                button: {
                    color: '#22BC66', // Optional action button color
                    text: 'Reset your Password',
                    link: resetPasswordUrl
                }
            },
            outro: 'Need help, or have questions? Just reply to this email, we\'d love to help.'
        }
    }
};

export { sendMail, emailVerificationMail, forgotPasswordMail };