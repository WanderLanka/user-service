const User = require('../models/User');
const Tempuser = require('../models/Tempuser');
const TokenService = require('./tokenService');

class Adminservice {
    static async requests(req, res) {
        const response = await Tempuser.find();
        const filtered = response.filter((tempuser) => tempuser.status === 'pending');
        return filtered;
    }

    static async updateRequestStatus(requestid, action) {
        const tempuser = await Tempuser.findById(requestid);
        if (!tempuser) {
            throw new Error('Request not found');
        }

        // frontend sends 'approved' or 'rejected'
        if (action === 'approved') {
            tempuser.status = 'approved';
            await tempuser.save();

            const newUser = new User({
                username: tempuser.username,
                email: tempuser.email,
                password: tempuser.password,
                role: tempuser.role,
                platform: tempuser.platform,
                emailVerified: tempuser.emailVerified || false,
                isActive: true,
                status: 'active'
            });

            if (tempuser.document) {
                if (tempuser.role === 'guide') {
                    newUser.guideDetails = newUser.guideDetails || {};
                    newUser.guideDetails.proofDocument = tempuser.document;
                } else {
                    newUser.avatar = tempuser.document;
                }
            }

            await newUser.save();
            return { user: newUser };

        } else if (action === 'rejected') {
            tempuser.status = 'rejected';
            await tempuser.save();
            return { message: 'Request rejected' };
        } else {
            throw new Error('Invalid action');
        }
    }
}

// Export as CommonJS so this service can be required from other CommonJS modules
module.exports = { default: Adminservice };