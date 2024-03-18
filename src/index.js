#!/usr/bin/env node

const EwelinkApi = require('ewelink-api-next').default;
const crypto = require('crypto');

class Ewelink {
	constructor(credentials) {
		if (credentials.appId && credentials.appSecret) {
			this.type = 'web';
			this.client = new EwelinkApi.WebAPI(credentials);
			this.client.at = credentials.at;
			this.client.rt = credentials.rt;
		}else{
			this.type = 'lan';
			this.client = new EwelinkApi.Lan({
				selfApikey: JSON.stringify(credentials)
			});
		}
	}
	encrypt(payload, devicekey) {
		const hash = crypto.createHash('md5').update(devicekey, 'utf-8').digest();

		const iv = crypto.randomBytes(16);
		const plaintext = Buffer.from(JSON.stringify(payload.data), 'utf-8');

		const cipher = crypto.createCipheriv('aes-128-cbc', hash, iv);

		const paddingLen = 16 - plaintext.length % 16;
		const padded = Buffer.concat([
			plaintext, Buffer.alloc(paddingLen, paddingLen)
		]);

		const ciphertext = Buffer.concat([
			cipher.update(padded), cipher.final()
		]);

		payload.encrypt = true;
		payload.data = ciphertext.toString('base64');
		payload.iv = iv.toString('base64');

		return payload;
	}
	decrypt(encryptedPayload, devicekey) {
		const hash = crypto.createHash('md5').update(devicekey, 'utf-8').digest();

		const iv = Buffer.from(encryptedPayload.iv, 'base64');
		const ciphertext = Buffer.from(encryptedPayload.data1, 'base64');

		const decipher = crypto.createDecipheriv('aes-128-cbc', hash, iv);
		const decrypted = Buffer.concat([
			decipher.update(ciphertext), decipher.final()
		]).toString('utf-8');
		return JSON.parse(decrypted);
	}
	getClient() {
		return this.client;
	}
	setStatus({ deviceid, devicekey, ip }, params) {
		if (this.type === 'web')
			return this.getClient().device.setThingStatus({ id: deviceid, params }).then(res => {
				if (res.error === 0)
					return { deviceid, devicekey, ip, params };
				else
					return Promise.reject({
						message: res.msg,
						code: res.error
					});
			});
		if (this.type === 'lan') {
			if (!ip)
				return Promise.reject({
					message: '"ip" is not allowed to be empty',
					code: 404
				});
			return this.getClient().request.request({
				url: 'http://'+ip+':8081/zeroconf/switch',
				method: 'post',
				headers: { 'Connection': 'close' },
				data: this.encrypt({
					sequence: '0',
					deviceid: deviceid,
					selfApikey: this.getClient().selfApikey,
					data: params
				}, devicekey)
			}).catch(err => {
				if (err.errno === -104)
					return {
						deviceid, devicekey, ip, params,
						error: 0
					};
				else
					return {
						msg: err,
						error: err.errno
					};
			}).then(res => {
				if (res.error === 0)
					return { deviceid, devicekey, ip, params };
				else
					return Promise.reject({
						message: res.msg,
						code: res.error
					});
			});
		}
	}
	getDevice(deviceid, devicekey) {
		if (this.type === 'web')
			return this.getClient().device.getThingStatus({ id: deviceid }).then(res => {
				if (res.error === 0)
					return {
						...res.data,
						deviceid, devicekey
					};
				else
					return Promise.reject({
						message: res.msg,
						code: res.error
					});
			});
		if (this.type === 'lan')
			return new Promise((res, rej) => {
				if (!deviceid)
					return rej({
						message: '"deviceid" is not allowed to be empty',
						code: 400
					});
				if (deviceid.length < 10)
					return rej({
						message: '"deviceid" length must be 10 characters long',
						code: 400
					});
				const timer = setTimeout(() => {
					bonjour.destroy();
					return rej({
						message: "get the device status error,can't find with deviceid:"+deviceid,
						code: 405
					});
				}, 2500);
				const bonjour = this.getClient().discovery(server => {
					if (server.txt.id === deviceid) {
						clearTimeout(timer);
						bonjour.destroy();
						const params = devicekey ? this.decrypt(server.txt, devicekey) : [];
						return res({
							params, devicekey,
							deviceid: server.txt.id,
							port: server.port,
							ip: server.addresses[0]
						});
					}
				});
			});
	}
	getDevices(keys) {
		if (this.type === 'web')
			return this.getClient().device.getAllThings().then(res => {
				if (res.error === 0)
					return res.data.thingList.map(item => item.itemData);
				else
					return Promise.reject({
						message: res.msg,
						code: res.error
					});
			});
		if (this.type === 'lan')
			return new Promise((res, rej) => {
				const devices = [];
				const timer = setTimeout(() => {
					bonjour.destroy();
					return res(devices);
				}, 2500);
				const bonjour = this.getClient().discovery(server => {
					const devicekey = keys?.find(device => (device.deviceid === server.txt.id))?.devicekey;
					const params = devicekey ? this.decrypt(server.txt, devicekey) : [];
					devices.push({
						params, devicekey,
						deviceid: server.txt.id,
						port: server.port,
						ip: server.addresses[0]
					});
				});
			});
	}
}

module.exports = Ewelink;
