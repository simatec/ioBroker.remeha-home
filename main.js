'use strict';

const utils = require('@iobroker/adapter-core');
const crypto = require('crypto');
const { URL } = require('url');
const { CookieJar } = require('tough-cookie');

const cookieJar = new CookieJar();

const adapterName = require('./package.json').name.split('.').pop();
let systemLang = 'de';

class RemehaHomeAdapter extends utils.Adapter {
    constructor(options) {
        super({ ...options, name: adapterName });
        this.got = null;
        this.account = '';
        this.password = '';
        this.pollInterval = 60;
        this.accessToken = null;
        this.refreshToken = null;
        this.csrfToken = null;
        this.codeChallenge = '';
        this.state = '';
        this.postUpdate = true;
        this.getUpdate = false;
        this.loadGot();

        this.onReady = this.onReady.bind(this);
        this.onStateChange = this.onStateChange.bind(this);
        this.onUnload = this.onUnload.bind(this);

        this.on('ready', this.onReady);
        this.on('stateChange', this.onStateChange);
        this.on('unload', this.onUnload);
    }

    async loadGot() {
        const { default: got } = await import('got');
        this.got = got;
        this.client = this.got.extend({
            prefixUrl: 'https://remehalogin.bdrthermea.net',
            timeout: {
                connect: 2000,
                request: 5000
            },
            cookieJar,
        });
    }

    async onReady() {
        this.log.info('Remeha Home Adapter started.');

        const language = await this.getForeignObjectsAsync('system.config');

        if (language && language.common && language.common.language) {
            systemLang = language.common.language;
        }

        this.account = this.config.account;
        this.password = this.config.password;
        this.pollInterval = parseInt(this.config.pollInterval, 10);

        if (isNaN(this.pollInterval) || this.pollInterval < 30) this.pollInterval = 30;
        if (this.pollInterval > 300) this.pollInterval = 300;

        this.subscribeStates('data.roomThermostat.setPoint');
        this.subscribeStates('data.roomThermostat.firePlaceModeActive');
        this.subscribeStates('data.roomThermostat.setZoneMode');

        await this.createDevices();
        this.schedulePoll();
    }

    async createDevices() {
        const states = [
            { id: 'data.roomThermostat.roomTemperature', name: 'Room Temperature', read: true, write: false, type: 'number', role: 'value.temperature', unit: '°C' },
            { id: 'data.dhw.outdoorTemperature', name: 'Outdoor Temperature', read: true, write: false, type: 'number', role: 'value.temperature', unit: '°C' },
            { id: 'data.dhw.waterPressure', name: 'Water Pressure', read: true, write: false, type: 'number', role: 'value.pressure', unit: 'bar' },
            { id: 'data.roomThermostat.setPoint', name: 'Set Point Temperature', read: true, write: true, type: 'number', role: 'value.temperature', unit: '°C' },
            { id: 'data.dhw.dhwTemperature', name: 'DHW Temperature', read: true, write: false, type: 'number', role: 'value.temperature', unit: '°C' },
            { id: 'data.dhw.dhwTargetSetpoint', name: 'DHW Target Setpoint', read: true, write: false, type: 'number', role: 'value.temperature', unit: '°C' },
            { id: 'data.dhw.dhwStatus', name: 'DHW Status', read: true, write: false, type: 'string', role: 'value' },
            { id: 'data.dhw.name', name: 'DHW Name', read: true, write: false, type: 'string', role: 'value' },
            { id: 'data.dhw.gasCalorificValue', name: 'Gas Calorific Value', read: true, write: false, type: 'number', role: 'value.power', unit: 'kWh/m³' },
            { id: 'data.roomThermostat.name', name: ' Thermostat Name', read: true, write: false, type: 'string', role: 'value' },
            { id: 'data.roomThermostat.setZoneMode', name: 'Set Zone Mode', role: 'level.mode.thermostat', read: true, write: true, type: 'string', states: { 'Scheduling': this.translate('Scheduling', systemLang), 'Manual': this.translate('Manual', systemLang), 'FrostProtection': this.translate('FrostProtection', systemLang) } },
            { id: 'data.roomThermostat.currentZoneMode', name: 'Current Zone Mode', role: 'level.mode.thermostat', read: true, write: false, type: 'string' },
            { id: 'data.dhw.waterPressureOK', name: 'Water Pressure OK', read: true, write: false, role: 'switch', type: 'boolean' },
            { id: 'data.roomThermostat.firePlaceModeActive', name: 'Fireplace Mode Active', read: true, write: true, role: 'switch', type: 'boolean' },
            { id: 'data.roomThermostat.nextSetpoint', name: 'next Setpoint', read: true, write: false, role: 'value.temperature', type: 'number', unit: '°C' },
            { id: 'data.roomThermostat.currentScheduleSetPoint', name: 'current Schedule SetPoint', read: false, write: false, role: 'value.temperature', type: 'number', unit: '°C' },
            { id: 'data.roomThermostat.nextSwitchTime', name: 'next Switch Time', read: true, write: false, role: 'value.datetime', type: 'string' },
            { id: 'data.roomThermostat.activeComfortDemand', name: 'active Comfort Demand', read: true, write: false, role: 'value', type: 'string' },
            { id: 'info.deviceType', name: 'Device Type', read: true, write: false, role: 'value', type: 'string' },
            { id: 'info.serialNumber', name: 'Serial Number', read: true, write: false, role: 'value', type: 'string' },
            { id: 'info.softwareVersion', name: 'Software Version', read: true, write: false, role: 'value', type: 'string' },
            { id: 'info.hardwareVersion', name: 'Hardware Version', read: true, write: false, role: 'value', type: 'string' },
            { id: 'info.applianceName', name: 'Appliance Name', read: true, write: false, role: 'value', type: 'string' },
        ];

        for (const state of states) {
            await this.setObjectNotExistsAsync(state.id, {
                type: 'state',
                common: {
                    name: this.translate(state.name, systemLang),
                    type: state.type || 'number',
                    role: state.role,
                    unit: state.unit || '',
                    read: state.read,
                    write: state.write,
                    states: state.states || undefined,
                },
                native: {},
            });
        }
    }

    translate(word, systemLang) {
        const translations = require(`./admin/i18n/${systemLang ? systemLang : 'en'}/translations.json`);

        if (translations[word]) {
            return translations[word];
        } else {
            this.log.warn(`Please translate in translations.json: ${word}`);
            return word;
        }
    }

    schedulePoll() {
        this.poll();
        this.interval = setInterval(() => this.poll(), this.pollInterval * 1000);
    }

    async poll() {
        try {
            if (this.accessToken === null) {
                await this.resolveExternalData();
            } else if (this.accessToken !== null && await this.checkTokenValidity(this.accessToken) !== 200) {
                await this.refreshAccessToken();
            }
            if (await this.checkTokenValidity(this.accessToken) === 200 && this.postUpdate) {
                await this.updateDevices();
            }
        } catch (error) {
            this.log.error(`Polling error: ${error.message}`);
        }
    }

    async resolveExternalData() {
        try {
            this.state = crypto.randomBytes(32).toString('base64url');
            const codeChallenge = await this.generateRandomToken(64);
            this.codeChallenge = codeChallenge;
            const codeChallengeSha256 = await this.computeCodeChallenge(codeChallenge);

            const response = await this.client.get(`bdrb2cprod.onmicrosoft.com/oauth2/v2.0/authorize?`, {
                searchParams: {
                    response_type: 'code',
                    client_id: '6ce007c6-0628-419e-88f4-bee2e6418eec',
                    redirect_uri: 'com.b2c.remehaapp://login-callback',
                    scope: 'openid https://bdrb2cprod.onmicrosoft.com/iotdevice/user_impersonation offline_access',
                    state: this.state,
                    code_challenge: codeChallengeSha256,
                    code_challenge_method: 'S256',
                    p: 'B2C_1A_RPSignUpSignInNewRoomV3.1',
                    brand: 'remeha',
                    lang: 'en',
                    nonce: 'defaultNonce',
                    prompt: 'login',
                    signUp: 'False'
                },
                followRedirect: true,
            });

            this.log.debug(`Get Auth: ${response.statusCode === 200 ? 'OK' : 'failed'}`);

            let csrfTokenCookie;
            const cookies = response.headers['set-cookie'];
            if (cookies) {

                csrfTokenCookie = cookies.find(cookie => cookie.startsWith('x-ms-cpim-csrf=') && cookie.includes('domain=remehalogin.bdrthermea.net'));

                if (csrfTokenCookie) {
                    this.csrfToken = csrfTokenCookie.split(';')[0].replace("x-ms-cpim-csrf=", "").replace(/;$/, "");
                } else {
                    throw new Error('CSRF-Token not found in response headers.');
                }

            }

            // Extract the request_id from headers
            const requestId = response.headers['x-request-id'];

            // Create state_properties JSON and encode it in base64 URL-safe format
            const statePropertiesJson = `{"TID":"${requestId}"}`;
            const stateProperties = Buffer.from(statePropertiesJson)
                .toString('base64')
                .replace(/\+/g, '-')
                .replace(/\//g, '_')
                .replace(/=+$/, '');

            const authorizationCode = await this.login(stateProperties, this.csrfToken);

            if (!authorizationCode) throw new Error('Authorization code is missing.');

            await this.fetchAccessToken(authorizationCode);
        } catch (error) {
            this.log.error(`Error resolving external data: ${error.message}`);
        }
    }

    async login(stateProperties, csrfToken) {
        try {
            const response = await this.client.post(`bdrb2cprod.onmicrosoft.com/B2C_1A_RPSignUpSignInNewRoomv3.1/SelfAsserted`, {
                searchParams: {
                    tx: `StateProperties=${stateProperties}`,
                    p: 'B2C_1A_RPSignUpSignInNewRoomv3.1',
                },
                form: {
                    request_type: 'RESPONSE',
                    signInName: this.account,
                    password: this.password
                },
                headers: {
                    'x-csrf-token': csrfToken,
                },
                followRedirect: true,
            });

            this.log.debug(`Post Login Status: ${response.statusCode === 200 ? 'OK' : 'failed'}`);

        } catch (error) {
            this.log.error('Error during login:' + error.message);
            if (error.response) {
                this.log.error('Response status:' + error.response.status);
            }
            throw error;
        }

        try {
            const url = `bdrb2cprod.onmicrosoft.com/B2C_1A_RPSignUpSignInNewRoomv3.1/api/CombinedSigninAndSignup/confirmed`;
            const response = await this.client.get(url, {
                searchParams: {
                    rememberMe: 'false',
                    csrf_token: csrfToken,
                    tx: `StateProperties=${stateProperties}`,
                    p: 'B2C_1A_RPSignUpSignInNewRoomv3.1',
                },
                followRedirect: false
            });

            this.log.debug(`Get Login Status: ${response.statusCode === 302 ? 'OK' : 'failed'}`);

            const parsedCallbackUrl = new URL(response.headers.location);
            if (parsedCallbackUrl) {
                const queryStringDict = parsedCallbackUrl.searchParams;
                const code = queryStringDict.get('code');
                if (code) {
                    return code;
                } else {
                    this.log.debug('Authorization code not found');

                }
            } else {
                this.log.debug('No redirect URL found in response headers.');
            }
            this.log.debug('Authorization code not found in redirect URL.');
            return null;
        } catch (error) {
            this.log.error(`Error get code: ${error}`);
            if (error.response) {
                this.log.error(`Response error Status: ${error.response}`);
            }
            throw error;
        }
    }

    async generateRandomToken(length) {
        return crypto.randomBytes(length).toString('base64url');
    }

    async computeCodeChallenge(token) {
        const hash = crypto.createHash('sha256');
        hash.update(token);
        const digest = hash.digest();

        const base64Url = digest.toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');

        return base64Url;
    }

    async fetchAccessToken(code) {
        try {
            const grantParams = {
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: 'com.b2c.remehaapp://login-callback',
                code_verifier: this.codeChallenge,
                client_id: '6ce007c6-0628-419e-88f4-bee2e6418eec',
            };
            const response = await this.client.post('bdrb2cprod.onmicrosoft.com/oauth2/v2.0/token', {
                searchParams: {
                    p: 'B2C_1A_RPSignUpSignInNewRoomV3.1'
                },
                form: grantParams,
                followRedirect: true,
                responseType: 'json'
            });
            this.log.debug(`Get Accesstoken Status: ${response.statusCode === 200 ? 'OK' : 'failed'}`);
            this.accessToken = response.body.access_token;
            this.refreshToken = response.body.refresh_token;
            return this.accessToken;
        } catch (error) {
            this.log.error(`Error fetching access token: ${error}`);
            throw error;
        }
    }

    async refreshAccessToken() {
        try {
            const grantParams = {
                grant_type: 'refresh_token',
                refresh_token: this.refreshToken,
                client_id: '6ce007c6-0628-419e-88f4-bee2e6418eec'
            };

            const response = await this.client.post('bdrb2cprod.onmicrosoft.com/oauth2/v2.0/token', {
                searchParams: {
                    p: 'B2C_1A_RPSignUpSignInNewRoomV3.1'
                },
                form: grantParams,
                followRedirect: true,
                responseType: 'json'
            });

            this.log.debug(`Get Refreshtoken Status: ${response.statusCode === 200 ? 'OK' : 'failed'}`);
            this.accessToken = response.body.access_token;
        } catch (error) {
            this.log.error(`Error refreshing access token: ${error}`);
            throw error;
        }
    }

    async updateDevices() {
        try {
            this.getUpdate = true;

            const response = await this.got.get('https://api.bdrthermea.net/Mobile/api/homes/dashboard', {
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`,
                    'Ocp-Apim-Subscription-Key': 'df605c5470d846fc91e848b1cc653ddf',
                    'x-csrf-token': this.csrfToken
                }
            });
            this.log.debug(`Get Update Status: ${response.statusCode === 200 ? 'OK' : 'failed'}`);

            const data = JSON.parse(response.body);

            const _zoneMode = data.appliances[0].climateZones[0].zoneMode;
            const _zoneModeTranslate = this.translate(_zoneMode, systemLang);

            await this.setState('data.roomThermostat.roomTemperature', { val: data.appliances[0].climateZones[0].roomTemperature, ack: true });
            await this.setState('data.dhw.outdoorTemperature', { val: data.appliances[0].outdoorTemperature, ack: true });
            await this.setState('data.dhw.waterPressure', { val: data.appliances[0].waterPressure, ack: true });
            await this.setState('data.roomThermostat.setPoint', { val: data.appliances[0].climateZones[0].setPoint, ack: true });
            await this.setState('data.dhw.dhwTemperature', { val: data.appliances[0].hotWaterZones[0].dhwTemperature, ack: true });
            await this.setState('data.dhw.dhwTargetSetpoint', { val: data.appliances[0].hotWaterZones[0].targetSetpoint, ack: true });
            await this.setState('data.dhw.dhwStatus', { val: data.appliances[0].hotWaterZones[0].dhwStatus, ack: true });
            await this.setState('data.dhw.name', { val: data.appliances[0].hotWaterZones[0].name, ack: true });
            await this.setState('data.dhw.gasCalorificValue', { val: data.appliances[0].gasCalorificValue, ack: true });
            await this.setState('data.roomThermostat.currentZoneMode', { val: _zoneModeTranslate, ack: true });
            await this.setState('data.dhw.waterPressureOK', { val: data.appliances[0].waterPressureOK, ack: true });
            await this.setState('data.roomThermostat.firePlaceModeActive', { val: data.appliances[0].climateZones[0].firePlaceModeActive, ack: true });
            await this.setState('data.roomThermostat.name', { val: data.appliances[0].climateZones[0].name, ack: true });
            await this.setState('data.roomThermostat.nextSetpoint', { val: data.appliances[0].climateZones[0].nextSetpoint, ack: true });
            await this.setState('data.roomThermostat.currentScheduleSetPoint', { val: data.appliances[0].climateZones[0].currentScheduleSetPoint, ack: true });
            await this.setState('data.roomThermostat.activeComfortDemand', { val: data.appliances[0].climateZones[0].activeComfortDemand, ack: true });
            await this.setState('data.roomThermostat.nextSwitchTime', { val: data.appliances[0].climateZones[0].nextSwitchTime, ack: true });

            if (_zoneMode !== 'TemporaryOverride') {
                await this.setState('data.roomThermostat.setZoneMode', { val: _zoneMode, ack: true })
            }

            const appliance = await this.got.get(`https://api.bdrthermea.net/Mobile/api/appliances/${data?.appliances[0].applianceId}/technicaldetails`, {
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`,
                    'Ocp-Apim-Subscription-Key': 'df605c5470d846fc91e848b1cc653ddf',
                    'x-csrf-token': this.csrfToken
                }
            });

            this.log.debug(`Get Device Info Status: ${appliance.statusCode === 200 ? 'OK' : 'failed'}`);
            const applianceInfo = JSON.parse(appliance.body);

            await this.setState('info.applianceName', { val: applianceInfo.applianceName, ack: true });
            await this.setState('info.deviceType', { val: applianceInfo.internetConnectedGateways[0].deviceTypeName, ack: true });
            await this.setState('info.serialNumber', { val: applianceInfo.internetConnectedGateways[0].serialNumber, ack: true });
            await this.setState('info.softwareVersion', { val: applianceInfo.internetConnectedGateways[0].softwareVersion, ack: true });
            await this.setState('info.hardwareVersion', { val: applianceInfo.internetConnectedGateways[0].hardwareVersion, ack: true });

            this.getUpdate = false;
        } catch (error) {
            this.getUpdate = false;
            this.log.error(`Error updating devices: ${error}`);
        }
    }

    async checkTokenValidity(token) {
        try {
            const response = await this.got.get('https://api.bdrthermea.net/Mobile/api/homes/dashboard', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Ocp-Apim-Subscription-Key': 'df605c5470d846fc91e848b1cc653ddf',
                    'x-csrf-token': this.csrfToken
                }
            });
            this.log.debug(`Get checkTokenValidity Status: ${response.statusCode === 200 ? 'OK' : 'failed'}`);
            await this.setState('info.connection', response.statusCode === 200 ? true : false, true);

            return response.statusCode;
        } catch (error) {
            this.log.debug('Token validity check failed. An attempt is being made to obtain a new token');
            await this.setState('info.connection', false, true);
            return false;
        }
    }

    async setValues(type, postData) {
        if (this.accessToken === null) {
            await this.resolveExternalData();
        } else if (this.accessToken !== null && await this.checkTokenValidity(this.accessToken) !== 200) {
            await this.refreshAccessToken();
        }

        if (await this.checkTokenValidity(this.accessToken) === 200 && this.postUpdate) {
            this.postUpdate = false;

            const headers = {
                'Authorization': `Bearer ${this.accessToken}`,
                'Ocp-Apim-Subscription-Key': 'df605c5470d846fc91e848b1cc653ddf',
                'x-csrf-token': this.csrfToken
            }
            try {
                const response = await this.got.get('https://api.bdrthermea.net/Mobile/api/homes/dashboard', {
                    headers: headers
                });
                const responseJson = JSON.parse(response.body);

                const climateZoneId = responseJson.appliances[0].climateZones[0].climateZoneId;
                const valueSetpoint = responseJson.appliances[0].climateZones[0].setPoint;
                const valueFireplaceMode = responseJson.appliances[0].climateZones[0].firePlaceModeActive;
                const valueZoneMode = responseJson.appliances[0].climateZones[0].zoneMode;
                const valueProgNumber = responseJson.appliances[0].climateZones[0].activeHeatingClimateTimeProgramNumber;

                switch (type) {
                    case 'setPoint':
                        if (valueZoneMode !== 'Manual' || valueSetpoint !== postData?.roomTemperatureSetPoint) {
                            try {
                                const postResponse = await this.got.post(`https://api.bdrthermea.net/Mobile/api/climate-zones/${climateZoneId}/modes/${valueZoneMode !== 'Manual' ? 'temporary-override' : 'manual'}`, {
                                    headers: headers,
                                    json: postData,
                                    responseType: 'json'
                                });

                                this.log.debug(`Post SetPoint: ${postResponse.statusCode === 200 ? 'OK' : 'failed'}`);
                            } catch (postError) {
                                this.log.error(`Error making POST request SetPoint: ${postError}`);
                            }
                        } else {
                            this.log.debug('setpoint noChange');
                        }
                        break;
                    case 'fireplaceModeActive':
                        if (valueFireplaceMode !== postData?.firePlaceModeActive) {
                            try {
                                const postResponse = await this.got.post(`https://api.bdrthermea.net/Mobile/api/climate-zones/${climateZoneId}/modes/fireplacemode`, {
                                    headers: headers,
                                    json: postData,
                                    responseType: 'json'
                                });

                                this.log.debug(`Post fireplacemode: ${postResponse.statusCode === 200 ? 'OK' : 'failed'}`);
                            } catch (postError) {
                                this.log.error(`Error making POST request for fireplacemode: ${postError}`);
                            }
                        } else {
                            this.log.debug('fireplaceMode noChange');
                        }
                        break;
                    case 'zoneMode':
                        if (valueZoneMode !== postData?.zoneMode) {
                            const jsonData = postData?.zoneMode === 'Scheduling' ? { heatingProgramId: valueProgNumber } : postData?.zoneMode === 'Manual' ? { roomTemperatureSetPoint: valueSetpoint } : null;
                            try {
                                const postResponse = await this.got.post(`https://api.bdrthermea.net/Mobile/api/climate-zones/${climateZoneId}/modes/${postData?.value}`, {
                                    headers: headers,
                                    json: jsonData,
                                    responseType: 'json'
                                });

                                this.log.debug(`Post ZoneMode: ${postResponse.statusCode === 200 ? 'OK' : 'failed'}`);
                            } catch (postError) {
                                this.log.error(`Error making POST request for zoneMode: ${postError}`);
                            }
                        } else {
                            this.log.debug('zoneMode noChange');
                        }
                        break;
                }
                this.postUpdate = true;
                await this.updateDevices();
            } catch (getError) {
                this.postUpdate = true;
                this.log.error(`Error making GET request: ${getError}`);
            }
        }
    }

    async onStateChange(id, state) {
        if (state && !this.getUpdate) {
            if (id === `${this.namespace}.data.roomThermostat.setPoint`) {
                if (!state?.ack) {
                    await this.setState('data.roomThermostat.setPoint', { val: state?.val, ack: true });
                } else {

                    const postData = {
                        roomTemperatureSetPoint: state.val
                    };
                    this.setValues('setPoint', postData);
                }
            }

            if (id === `${this.namespace}.data.roomThermostat.setZoneMode`) {
                if (!state?.ack) {
                    await this.setState('data.roomThermostat.setZoneMode', { val: state?.val, ack: true });
                } else {
                    let mode = '';

                    switch (state.val) {
                        case 'Scheduling':
                            mode = 'schedule'
                            break;
                        case 'Manual':
                            mode = 'manual'
                            break;
                        case 'TemporaryOverride':
                            mode = 'temporary-override';
                            break;
                        case 'FrostProtection':
                            mode = 'anti-frost';
                            break;

                    }
                    const postData = {
                        zoneMode: state.val,
                        value: mode,
                    };
                    this.setValues('zoneMode', postData);
                }
            }

            if (id === `${this.namespace}.data.roomThermostat.firePlaceModeActive`) {
                if (!state?.ack) {
                    await this.setState('data.roomThermostat.firePlaceModeActive', { val: state?.val, ack: true });
                } else {
                    const postData = {
                        fireplaceModeActive: state.val
                    };
                    this.setValues('fireplaceModeActive', postData);
                }
            }
        }
    }

    onUnload(callback) {
        try {
            this.setState('info.connection', false, true);
            this.clearInterval(this.interval);
            callback();
        } catch (e) {
            callback();
        }
    }
}

if (module.parent) {
    module.exports = (options) => new RemehaHomeAdapter(options);
} else {
    new RemehaHomeAdapter();
}
