module.exports = RED => {
	const Ewelink = require('./index.js');
	function Config(config) {
		RED.nodes.createNode(this, config);
		this.setDevices = function(devices) {
			if (JSON.stringify(this.credentials.devices) != JSON.stringify(devices)) {
				this.credentials.devices = devices;
				RED.nodes.addCredentials(this.id, this.credentials);
			}
			return this;
		}
		this.getDevices = function(devices) {
			return [].concat(this.credentials.devices, devices).filter(device => (device && (typeof(device) === 'object')));
		}
		this.getDevice = function(deviceid, devices) {
			if (!deviceid)
				return;
			return this.getDevices(devices).find(device => (device.deviceid === deviceid));
		}
		this.getClient = async function() {
			const currentTime = (new Date()).getTime();
			const ewelink = new Ewelink(this.credentials);
			if (ewelink.client && ewelink.client.appId && (ewelink.client.atExpiredTime <= currentTime)) {
				return ewelink.client.user.refreshToken({
					rt: ewelink.client.rt
				}).then(res => {
					if (res.error === 0) {
						this.credentials.at = res.data.accessToken;
						this.credentials.rt = res.data.refreshToken;
						this.credentials.atExpiredTime = res.data.atExpiredTime || (currentTime + (24*60*60*1000*29));
						this.credentials.rtExpiredTime = res.data.rtExpiredTime || (currentTime + (24*60*60*1000*59));
						RED.nodes.addCredentials(this.id, this.credentials);
						ewelink.client.at = this.credentials.at;
						ewelink.client.rt = this.credentials.rt;
						ewelink.client.atExpiredTime = this.credentials.atExpiredTime;
						return ewelink;
					}else
						this.error('Error during refresh of the token: '+res.msg, {
							code: res.error
						});
				});
			}else
				return ewelink;
		}
	}
	RED.nodes.registerType('ewelink-config', Config, {
		credentials: {
			devices: { type: 'text' },
			appId: { type: 'text' },
			appSecret: { type: 'password' },
			redirectUrl: { type: 'text' },
			csrfToken: { type: 'text' },
			region: { type: 'text' },
			at: { type: 'password' },
			rt: { type: 'password' }
		}
	});
	RED.httpAdmin.get('/ewelink/auth', function(req, res) {
		if (!req.query.appId || !req.query.appSecret || !req.query.id || !req.query.redirectUrl)
			return res.status(400).send({
				code: 'eWeLink.error.noparams',
				message: 'missing parameters'
			});
		const crypto = require('crypto');
		const url = require('url');

		const nodeId = req.query.id;
		const credentials = {
			csrfToken: crypto.randomBytes(18).toString('base64').replace(new RegExp('/', 'g'), '-').replace(new RegExp('\\+', 'g'), '_'),
			appId: req.query.appId,
			appSecret: req.query.appSecret,
			redirectUrl: req.query.redirectUrl
		};

		const seq = Date.now();
		const buffer = Buffer.from(credentials.appId+'_'+seq, 'utf-8');
		const authorization = crypto.createHmac('sha256', credentials.appSecret).update(buffer).digest('base64');

		let nonce = '';
		let counter = 0;
		const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		const charactersLength = characters.length;
		while (counter < 8) {
			nonce += characters.charAt(Math.floor(Math.random() * charactersLength));
			counter += 1;
		}

		res.redirect(url.format({
			protocol: 'https',
			hostname: 'c2ccdn.coolkit.cc',
			pathname: '/oauth/index.html',
			query: {
				seq, nonce, authorization,
				clientId: credentials.appId,
				redirectUrl: credentials.redirectUrl,
				state: nodeId+':'+credentials.csrfToken,
				grantType: 'authorization_code'
			}
		}));
		RED.nodes.addCredentials(nodeId, credentials);
	});
	RED.httpAdmin.get('/ewelink/callback', function(req, res) {
		if (req.query.error)
			return res.status(401).send({
				code: 'eWeLink.error.error',
				message: {
					error: req.query.error,
					description: req.query.error_description
				}
			});
		if (!req.query || !req.query.state || !req.query.code || !req.query.region)
			return res.status(401).send({
				code: 'eWeLink.error.noparams',
				message: 'missing parameters'
			});

		const state = req.query.state.split(':');
		const nodeId = state[0];
		const credentials = RED.nodes.getCredentials(nodeId);

		if (!credentials || !credentials.appId || !credentials.appSecret)
			return res.status(401).send({
				code: 'ewelink.error.no-credentials',
				message: 'The node is not retreivable or there is no credentials for it'
			});
		if (state[1] !== credentials.csrfToken)
			return res.status(401).send({
				code: 'ewelink.error.token-mismatch',
				message: 'Incorrect token'
			});

		const { client } = new ewelink(credentials);
		client.oauth.getToken({
			code: req.query.code,
			region: req.query.region,
			redirectUrl: credentials.redirectUrl,
			grantType: 'authorization_code'
		}).then(resp => {
			if (resp.error === 0) {
				credentials.region = req.query.region;
				credentials.at = resp.data.accessToken;
				credentials.rt = resp.data.refreshToken;
				credentials.atExpiredTime = resp.data.atExpiredTime;
				credentials.rtExpiredTime = resp.data.rtExpiredTime;
				RED.nodes.addCredentials(nodeId, credentials);
				res.send('<script>window.setTimeout(window.close,5000);</script> Authorized ! The page will automatically close in 5s.');
			}else
				return res.status(401).send({
					code: 'ewelink.error.api-error',
					message: 'Could not receive tokens ['+resp.error+']: '+resp.msg
				});
		}).catch((error) => {
			return res.status(401).send({
				code: 'ewelink.error.token-mismatch',
				message: 'Could not receive tokens: '+error
			});
		});
	});
}
