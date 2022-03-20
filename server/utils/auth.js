// Set up JSON web token
// See typeDefs.js for the Auth typedef, and its implementation in the Mutation typedef

const jwt = require('jsonwebtoken');

const secret = 'mysecrets';
const expiration = '2h';

module.exports = {

    // signToken() adds user's username, email and _id to the token.
    // This'll be exported to resolvers.js
    signToken: function({ username, email, _id }) {
        const payload = { username, email, _id };
        // "secret" has nothing to do with encoding. It merely enables the server to verify whether it recognizes this token.
        return jwt.sign({ data: payload }, secret, { expiresIn: expiration });
    },

    // This is exported to server.js
    authMiddleware: function({ req }) {
        // allows auth token to be sent via req.body, req.query or headers
        let token = req.body.token || req.query.token || req.headers.authorization;

        // separate "Bearer" from "<tokenvalue>"
        if (req.headers.authorization) {
            token = token
                .split(' ')
                .pop()
                .trim();
        }

        // if no token, return request object as is
        if (!token) {
            return req;
        }

        try {
            // decode and attach user data to request object
            // if the secret on jwt.verify() doesnt match what's in jwt.sign() (see signToken function), an error is thrown
            const { data } = jwt.verify(token, secret, { maxAge: expiration });
            req.user = data;
        } catch {
            console.log('Invalid token');
        }

        // return updated request object
        return req;
    }
};