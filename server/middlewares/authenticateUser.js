module.exports = function(req, res, next) {
    if (!req.session.user.admin) {
        res.status(403).send('Cool your jets, Jimmy!')
    } else {
        next();
    }
}