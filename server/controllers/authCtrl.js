const bcrypt = require('bcryptjs');

module.exports = {
    register: async (req, res) => {
        // bring in our db
        const db = req.app.get('db');

        // receive the information to eventually add a new user
        const { name, email, password, admin} = req.body;

        // check if an existing user matches the email trying to be registered with. if so, reject
        try {
            const [existingUser] = await db.get_user_by_email(email)

            if (existingUser) {
                return res.status(409).send('User already exists')
            }

            // hash and salt the password
            const salt = bcrypt.genSaltSync(10);
            const hash = bcrypt.hashSync(password, salt)

            // add the user to the db and get back their id
            const [ newUser ] = await db.register_user(name, email, hash, admin);

            // create a session for the user using the db response
            req.session.user = newUser;

            // send a response that includes the user session info
            res.status(200).send(newUser);

        } catch(err) {
            console.log(err);
            return res.sendStatus(500);
        }
    },
    login: (req, res) => {
        // get db instance
        const db = req.app.get('db'); 

        // get necessary info from req.body
        const { email, password } = req.body;
        
        // check if that user exists, if they do NOT, reject request
        db.get_user_by_email(email)
            .then(([existingUser]) => {
                if (!existingUser) {
                    return res.status(403).send('Incorrect email')
                }

                // compare the password from req.body with the stored hash that we just retrieved..if mismatch, reject
                const isAuthenticated = bcrypt.compareSync(password, existingUser.hash)

                if (!isAuthenticated) {
                    return res.status(403).send('Incorrect password')
                }
                // set up our session and be sure to not include the hash in the session
                delete existingUser.hash;

                req.session.user = existingUser;

                // send the response and session to the front
                res.status(200).send(req.session.user)
            })
    },
    logout: (req, res) => {
        req.session.destroy();
        res.sendStatus(200);
    }
}