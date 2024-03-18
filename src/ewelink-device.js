module.exports = RED => {
	function Device(config) {
		RED.nodes.createNode(this, config);
		const settings = RED.nodes.getNode(config.settings);
		this.on('input', msg => {
			const deviceid = RED.util.evaluateNodeProperty(config.deviceid, config.deviceidType, this, msg);
			const device = settings.getDevice(deviceid, msg.payload);
			const params = RED.util.evaluateNodeProperty(config.params, config.paramsType, this, msg);
			const topic = RED.util.evaluateNodeProperty(config.topic, config.topicType, this, msg);
			settings.getClient().then(client => {
				if (params)
					return client.setStatus(device, params);
				else
					return client.getDevice(deviceid, device?.devicekey);
			})
			.then(payload => this.send({
				...(topic && { topic }),
				payload
			}))
			.catch(({ message, code }) => this.error(message, { code }));
		});
	}
	RED.nodes.registerType('ewelink-device', Device);
}
