var Authorizer = require('../lib/authorizer')
var Session = require('../lib/session')
var path = require('path')
var tap = require('tap')
var nock = require('nock')

var userComplete = {name: 'bcoe', email: 'ben@example.com', accessToken: 'abc123'}
var invalidUserComplete = {name: 'bcoe', email: 'batman@example.com', accessToken: 'abc123'}
var userNotComplete = {name: 'bcoe', email: 'ben@example.com'}

var session = new Session()

require('chai').should()

process.env.OAUTH2_AUTHORIZATION_PATH = 'https://auth.example.com'
process.env.OAUTH2_PROFILE = 'https://api.github.com/user'

tap.test('it responds with session object if SSO dance is complete', function (t) {
  var authorizer = new Authorizer({
    userWhitelistPath: path.resolve(__dirname, './fixtures/user-whitelist.txt')
  })
  var profile = nock('https://api.github.com')
    .get('/user')
    .reply(200)

  session.unlock('ben@example.com-abc123')

  session.set('ben@example.com-abc123', userComplete, function (err) {
    t.equal(err, null)
    authorizer.authorize({
      headers: {
        authorization: 'Bearer ben@example.com-abc123'
      }
    }, function (err, user) {
      authorizer.end()
      session.unlock('ben@example.com-abc123')
      session.delete('ben@example.com-abc123')

      profile.done()
      t.equal(err, null)
      t.equal(user.email, 'ben@example.com')
      t.end()
    })
  })
})

tap.test('it responds with 402 if user is not in whitelist', function (t) {
  var authorizer = new Authorizer({
    userWhitelistPath: path.resolve(__dirname, './fixtures/user-whitelist.txt')
  })
  session.unlock('batman@example.com-abc123')

  session.set('batman@example.com-abc123', invalidUserComplete, function (err) {
    t.equal(err, null)
    authorizer.authorize({
      headers: {
        authorization: 'Bearer batman@example.com-abc123'
      }
    }, function (err, user) {
      authorizer.end()
      session.unlock('batman@example.com-abc123')
      session.delete('batman@example.com-abc123')
      err.message.should.match(/batman@example\.com is not currently part of the npm Enterprise trial/)
      t.done()
    })
  })
})

tap.test('does not check github if request is within timeout window', function (t) {
  var authorizer = new Authorizer({
    userWhitelistPath: path.resolve(__dirname, './fixtures/user-whitelist.txt')
  })

  session.lock('ben@example.com-abc123')
  session.set('ben@example.com-abc123', userComplete, function (err) {
    t.equal(err, null)
    authorizer.authorize({
      headers: {
        authorization: 'Bearer ben@example.com-abc123'
      }
    }, function (err, user) {
      authorizer.end()
      session.delete('ben@example.com-abc123')
      session.unlock('ben@example.com-abc123')

      t.equal(err, null)
      t.equal(user.email, 'ben@example.com')
      t.end()
    })
  })
})

tap.test('it returns error with login url if access token is no longer valid', function (t) {
  var authorizer = new Authorizer({
    userWhitelistPath: path.resolve(__dirname, './fixtures/user-whitelist.txt')
  })
  var profile = nock('https://api.github.com')
    .get('/user')
    .reply(401)

  session.set('ben@example.com-abc123', userComplete, function (err) {
    t.equal(err, null)
    authorizer.authorize({
      headers: {
        authorization: 'Bearer ben@example.com-abc123'
      }
    }, function (err, user) {
      authorizer.end()
      session.delete('ben@example.com-abc123')
      session.unlock('ben@example.com-abc123')

      profile.done()
      t.ok(err.message.indexOf('visit https://auth.example.com') !== -1)
      t.end()
    })
  })
})

tap.test('it returns error with login url if SSO dance is not complete', function (t) {
  var authorizer = new Authorizer({
    userWhitelistPath: path.resolve(__dirname, './fixtures/user-whitelist.txt')
  })
  session.set('ben@example.com-abc123', userNotComplete, function (err) {
    t.equal(err, null)
    authorizer.authorize({
      headers: {
        authorization: 'Bearer ben@example.com-abc123'
      }
    }, function (err, user) {
      authorizer.end()
      session.delete('ben@example.com-abc123')
      session.unlock('ben@example.com-abc123')

      t.ok(err.message.indexOf('visit https://auth.example.com') !== -1)
      t.end()
    })
  })
})

tap.test('it indicates that upstream caching is not allowed with OAuth-verified response', t => {
  var authorizer = new Authorizer({
    userWhitelistPath: path.resolve(__dirname, './fixtures/user-whitelist.txt')
  })
  var profile = nock('https://api.github.com')
    .get('/user')
    .reply(200)

  session.unlock('ben@example.com-abc123')

  session.set('ben@example.com-abc123', userComplete, function (err) {
    t.equal(err, null)
    authorizer.authorize({
      headers: {
        authorization: 'Bearer ben@example.com-abc123'
      }
    }, function (err, user) {
      authorizer.end()
      session.unlock('ben@example.com-abc123')
      session.delete('ben@example.com-abc123')

      profile.done()
      t.equal(err, null)
      t.equal(user.email, 'ben@example.com')
      t.equal(user.cacheAllowed, false)
      t.end()
    })
  })
})

tap.test('it indicates that upstream caching is not allowed with cached response', t => {
  var authorizer = new Authorizer({
    userWhitelistPath: path.resolve(__dirname, './fixtures/user-whitelist.txt')
  })

  session.lock('ben@example.com-abc123')
  session.set('ben@example.com-abc123', userComplete, function (err) {
    t.equal(err, null)
    authorizer.authorize({
      headers: {
        authorization: 'Bearer ben@example.com-abc123'
      }
    }, function (err, user) {
      authorizer.end()
      session.delete('ben@example.com-abc123')
      session.unlock('ben@example.com-abc123')

      t.equal(err, null)
      t.equal(user.email, 'ben@example.com')
      t.equal(user.cacheAllowed, false)
      t.end()
    })
  })
})

tap.test('after', function (t) {
  session.end(true)
  t.end()
})
