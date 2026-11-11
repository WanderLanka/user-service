const User = require('../models/User');
const Tempuser = require('../models/Tempuser');
const UserService = require('./userService');

class Adminservice {
  static async requests() {
    const [providers, guides] = await Promise.all([
      Tempuser.find({ status: 'pending' }).select('-password').lean(),
      User.find({ role: 'guide', status: 'pending' }).select('-password -refreshTokens').lean()
    ]);
    return [...providers, ...guides.map(guide => ({ ...guide, document: guide.guideDetails?.proofDocument }))];
  }

  static async updateRequestStatus(requestId, action) {
    if (!['approved', 'rejected'].includes(action)) throw new Error('Invalid action');
    const tempuser = await Tempuser.findById(requestId);
    if (!tempuser) {
      // Mobile guide registration stores a pending User rather than a TempUser.
      const guide = await User.findOneAndUpdate(
        { _id: requestId, role: 'guide', status: 'pending' },
        { $set: { status: action === 'approved' ? 'active' : 'rejected' } },
        { new: true, runValidators: true }
      );
      if (!guide) throw new Error('Pending request not found');
      await UserService.notifyGuideServiceSync(guide);
      return { user: UserService.formatUserResponse(guide) };
    }
    if (tempuser.status !== 'pending') throw new Error('Request has already been processed');
    if (action === 'rejected') {
      tempuser.status = 'rejected';
      await tempuser.save();
      return { message: 'Request rejected' };
    }
    // Persist the approved account before completing the request; failed saves
    // leave the request pending and retryable. Unique user indexes prevent duplicates.
    const newUser = await User.findOneAndUpdate(
      { username: tempuser.username, email: tempuser.email },
      { $setOnInsert: {
        username: tempuser.username, email: tempuser.email, password: tempuser.password,
        role: tempuser.role, platform: tempuser.platform,
        emailVerified: tempuser.emailVerified || false, isActive: true, status: 'active',
        ...(tempuser.document ? tempuser.role === 'guide' ? { guideDetails: { proofDocument: tempuser.document } } : {} : {})
      } },
      { upsert: true, new: true, runValidators: true }
    );
    tempuser.status = 'approved';
    await tempuser.save();
    await UserService.notifyGuideServiceSync(newUser);
    return { user: UserService.formatUserResponse(newUser) };
  }
}
module.exports = { default: Adminservice };
