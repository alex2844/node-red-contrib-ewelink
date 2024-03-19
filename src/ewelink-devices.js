module.exports = RED => {
	function Devices(config) {
		RED.nodes.createNode(this, config);
		const settings = RED.nodes.getNode(config.settings);
		this.on('input', msg => {
			settings.getClient().then(client => client.getDevices(settings.getDevices(msg.payload)))
			.then(payload => {
				if (msg.payload) {
					const devices = settings.getDevices();
					payload.forEach(({ deviceid, devicekey, address }) => {
						if (deviceid && devicekey && address) {
							const i = devices.findIndex(device => (device.deviceid === deviceid));
							if (i !== -1)
								devices[i] = { deviceid, devicekey, address };
							else
								devices.push({ deviceid, devicekey, address });
						}
					});
					settings.setDevices(devices);
				}
				return this.send({ payload });
			})
			.catch(({ message, code }) => this.error(message, { code }));
		});
	}
	RED.nodes.registerType('ewelink-devices', Devices);
}
