const { test } = require('node:test');
const assert = require('node:assert/strict');
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'automated-test-secret-with-at-least-32-characters';
const serve = require('./http.cjs');

test('admin endpoints reject anonymous and ordinary authenticated users', async t => {
  const app = require('../app');
  const jwt = require('jsonwebtoken');
  const token = jwt.sign({ userId: '507f1f77bcf86cd799439011', role: 'traveller' }, process.env.JWT_SECRET);
  const request = await serve(t, app);
  for (const [method, path] of [['GET', '/requests'], ['PUT', '/updateRequestStatus'], ['GET', '/requests/123/document'], ['POST', '/cleanup-tokens'], ['POST', '/cleanup-expired-otps']]) {
    assert.equal((await request(path, { method })).status, 401);
    assert.equal((await request(path, { method, headers: { Authorization: `Bearer ${token}` } })).status, 403);
  }
  assert.equal((await request('/uploads/docs/private.pdf')).status, 404);
});

test('password hash verifies the correct password and rejects another', async () => {
  const TokenService = require('../services/tokenService');
  const hash = await TokenService.hashPassword('TestPass123!');
  assert.notEqual(hash, 'TestPass123!');
  assert.equal(await TokenService.comparePassword('TestPass123!', hash), true);
  assert.equal(await TokenService.comparePassword('wrong-password', hash), false);
});

test('wrong OTP guesses increment the active challenge without filtering by the incorrect OTP', async t => {
  const Reset = require('../models/PasswordReset');
  let args;
  t.mock.method(Reset, 'updateOne', (...values) => { args = values; return Promise.resolve({ modifiedCount: 1 }); });
  await Reset.incrementAttempts('PERSON@example.com', 'wrong-code');
  assert.equal(args[0].email, 'person@example.com');
  assert.equal(args[0].otp, undefined);
  assert.deepEqual(args[0].attempts, { $lt: 3 });
  assert.deepEqual(args[1], { $inc: { attempts: 1 } });
});

test('tokens issued within one second are unique for safe refresh rotation', () => {
  const Service = require('../services/tokenService');
  const user = { _id: '507f1f77bcf86cd799439011', username: 'person', role: 'traveller' };
  const first = Service.generateTokens(user);
  const second = Service.generateTokens(user);
  assert.notEqual(first.refreshToken, second.refreshToken);
  assert.notEqual(first.accessToken, second.accessToken);
});

test('mobile guide approval updates a pending guide and synchronizes the guide service', async t => {
  const Temp = require('../models/Tempuser');
  const User = require('../models/User');
  const UserService = require('../services/userService');
  t.mock.method(Temp, 'findById', async () => null);
  const guide = { _id: '507f1f77bcf86cd799439011', username: 'guide-person', email: 'guide@example.com', role: 'guide', status: 'active' };
  t.mock.method(User, 'findOneAndUpdate', async (filter, update) => {
    assert.equal(filter.status, 'pending');
    assert.equal(update.$set.status, 'active');
    return guide;
  });
  const sync = t.mock.method(UserService, 'notifyGuideServiceSync', async () => {});
  const result = await require('../services/adminservice').default.updateRequestStatus(guide._id, 'approved');
  assert.equal(result.user.status, 'active');
  assert.equal(sync.mock.callCount(), 1);
});
