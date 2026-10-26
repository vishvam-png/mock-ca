
const jwt = require('jsonwebtoken');

module.exports = function requireAuth(req, res, next) {
  // 1. Read the Authorization header
  const authHeader = req.headers.authorization ?? '';

  // 2. Extract the Bearer token using the required strict regex
  const match = authHeader.match(/^Bearer ([^\s]+)$/i);
  const token = match ? match[1] : null;

  // 3. Reject requests without a valid Bearer token
  if (token === null) {
    return res.status(401).json({
      error: {
        code: 'AUTH_REQUIRED',
        message: 'Authentication required'
      }
    });
  }

  try {
    // 4. Verify the JWT
    const payload = jwt.verify(
      token,
      process.env.JWT_SECRET,
      { algorithms: ['HS256'] }
    );

    // 5. Attach the verified payload to the request
    req.user = payload;

    // 6. Continue to the route handler
    return next();
  } catch (err) {
    // 7. Return the same generic response for every verification error
    return res.status(401).json({
      error: {
        code: 'AUTH_REQUIRED',
        message: 'Authentication required'
      }
    });
  }
};
