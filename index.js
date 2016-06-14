const thunkify = require('thunkify')
const _JWT = require('jsonwebtoken')
const unless = require('koa-unless')
const util = require('util')

// Make verify function play nice with co/koa
const JWT = {decode: _JWT.decode, sign: _JWT.sign, verify: thunkify(_JWT.verify)}

module.exports = function (opts) {
  opts = opts || {}
  opts.key = opts.key || 'user'

  const tokenResolvers = [resolveCookies, resolveAuthorizationHeader]

  if (opts.getToken && util.isFunction(opts.getToken)) {
    tokenResolvers.unshift(opts.getToken)
  }

  const middleware = function * jwt (next) {
    let token, err, user, secret

    for (let i = 0; i < tokenResolvers.length; i++) {
      let output = tokenResolvers[i].call(this, opts)

      if (output) {
        token = output
        break
      }
    }

    if (!token && !opts.passthrough) {
      this.throw(401, 'No authentication token found\n')
    }

    secret = (this.state && this.state.secret) ? this.state.secret : opts.secret
    if (!secret) {
      this.throw(500, 'Invalid secret\n')
    }

    try {
      user = yield JWT.verify(token, secret, opts)
    } catch (e) {
      err = e
    }

    if (user || opts.passthrough) {
      this.state = this.state || {}
      this.state[opts.key] = user
      yield next
    } else {
      // 针对过期token增加408 code
      let code = err.name === 'TokenExpiredError' ? 408 : 401
      let msg = 'Invalid token' + (opts.debug ? ' - ' + err.message + '\n' : '\n')
      this.throw(code, msg)
    }
  }

  middleware.unless = unless

  return middleware
}

/**
 * resolveAuthorizationHeader - Attempts to parse the token from the Authorization header
 *
 * This function checks the Authorization header for a `Bearer <token>` pattern and return the token section
 *
 * @this The ctx object passed to the middleware
 *
 * @param  {object}      opts The middleware's options
 * @return {String|null}      The resolved token or null if not found
 */
function resolveAuthorizationHeader (opts) {
  if (!this.header || !this.header.authorization) {
    return
  }

  let parts = this.header.authorization.split(' ')

  if (parts.length === 2) {
    let scheme = parts[0]
    let credentials = parts[1]

    if (/^Bearer$/i.test(scheme)) {
      return credentials
    }
  } else {
    if (!opts.passthrough) {
      this.throw(401, 'Bad Authorization header format. Format is "Authorization: Bearer <token>"\n')
    }
  }
}

/**
 * resolveCookies - Attempts to retrieve the token from a cookie
 *
 * This function uses the opts.cookie option to retrieve the token
 *
 * @this The ctx object passed to the middleware
 *
 * @param  {object}      opts This middleware's options
 * @return {String|null}      The resolved token or null if not found
 */
function resolveCookies (opts) {
  if (opts.cookie && this.cookies.get(opts.cookie)) {
    return this.cookies.get(opts.cookie)
  }
}

// Export JWT methods as a convenience
module.exports.sign = _JWT.sign
module.exports.verify = _JWT.verify
module.exports.decode = _JWT.decode
