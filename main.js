'use strict';

const utils = require('@iobroker/adapter-core');
const crypto = require('crypto');
const { URL } = require('url');

const { CookieJar } = require('tough-cookie');

const cookieJar = new CookieJar();

class RemehaHomeAdapter extends utils.Adapter {
    constructor(options) {
        super({ ...options, name: 'remeha-home' });
        this.got = null;
        this.account = '';
        this.password = '';
        this.pollInterval = 60;
        this.accessToken = null;
        this.refreshToken = null;
        this.csrfToken = null;
        this.codeChallenge = '';
        this.state = '';
        this.loadGot();


        this.onReady = this.onReady.bind(this);
        this.onMessage = this.onMessage.bind(this);
        this.onStateChange = this.onStateChange.bind(this);
        this.onUnload = this.onUnload.bind(this);

        this.on('ready', this.onReady);
        this.on('message', this.onMessage);
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
        this.account = this.config.account;
        this.password = this.config.password;
        this.pollInterval = parseInt(this.config.pollInterval, 10);

        if (isNaN(this.pollInterval) || this.pollInterval < 30) this.pollInterval = 30;
        if (this.pollInterval > 300) this.pollInterval = 300;

        await this.createDevices();
        this.schedulePoll();
    }

    async createDevices() {
        const states = [
            { id: 'roomTemperature', name: 'Room Temperature', role: 'value.temperature', unit: '°C' },
            { id: 'outdoorTemperature', name: 'Outdoor Temperature', role: 'value.temperature', unit: '°C' },
            { id: 'waterPressure', name: 'Water Pressure', role: 'value.pressure', unit: 'bar' },
            { id: 'setPoint', name: 'Set Point Temperature', role: 'value.temperature', unit: '°C' },
            { id: 'dhwTemperature', name: 'DHW Temperature', role: 'value.temperature', unit: '°C' },
            { id: 'EnergyConsumption', name: 'Energy Consumption', role: 'value.power', unit: 'kWh' },
            { id: 'gasCalorificValue', name: 'Gas Calorific Value', role: 'value.power', unit: 'kWh/m³' },
            { id: 'zoneMode', name: 'Zone Mode', role: 'value', states: { 0: 'Scheduling', 10: 'Manual', 20: 'TemporaryOverride', 30: 'FrostProtection' } },
            { id: 'waterPressureToLow', name: 'Water Pressure Too Low', role: 'indicator', type: 'boolean' },
            { id: 'EnergyDelivered', name: 'Energy Delivered', role: 'value.power', unit: 'kWh' }
        ];

        for (const state of states) {
            await this.setObjectNotExistsAsync(state.id, {
                type: 'state',
                common: {
                    name: state.name,
                    type: state.type || 'number',
                    role: state.role,
                    unit: state.unit || '',
                    read: true,
                    write: state.id === 'setPoint',
                    states: state.states || undefined,
                },
                native: {},
            });
        }
    }

    schedulePoll() {
        this.poll();
        this.interval = setInterval(() => this.poll(), this.pollInterval * 1000);
    }

    async poll() {
        try {
            if (this.accessToken === null || await this.checkTokenValidity(this.accessToken) !== 200) {
                await this.resolveExternalData();
            }
            await this.updateDevices();
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

            this.log.debug('Response get Auth: ' + response.statusCode);

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

    async sleep(ms) {
        return new Promise(async (resolve) => {
            // @ts-ignore
            this.setTimeout(async () => resolve(), ms);
        });
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

            this.log.debug('Login response status:' + response.statusCode);

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

            this.log.debug('Login response1 status:' + response.statusCode);

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
                this.log.error(`Response error status: ${error.response}`);
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
            this.log.debug('Access Token Stattus:' + response.statusCode);
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
                form: grantParams,
                followRedirect: true,
                responseType: 'json'
            });

            this.accessToken = response.body.access_token;
            this.log.debug(`Refreshed Access Token: ${this.accessToken}`);
        } catch (error) {
            this.log.error(`Error refreshing access token: ${error}`);
            throw error;
        }
    }

    async updateDevices() {
        try {
            if (this.accessToken === null) {
                await this.fetchAccessToken();
            } else if (await this.checkTokenValidity(this.accessToken) !== 200) {
                await this.refreshAccessToken();
            }

            const response = await this.got.get('https://api.bdrthermea.net/Mobile/api/homes/dashboard', {
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`,
                    'Ocp-Apim-Subscription-Key': 'df605c5470d846fc91e848b1cc653ddf',
                    'x-csrf-token': this.csrfToken
                }
            });
            this.log.debug('Status Update: ' + response.statusCode)
            const data = JSON.parse(response.body);

            await this.setStateAsync('roomTemperature', { val: data.appliances[0].climateZones[0].roomTemperature, ack: true });
            await this.setStateAsync('outdoorTemperature', { val: data.appliances[0].outdoorTemperature, ack: true });
            await this.setStateAsync('waterPressure', { val: data.appliances[0].waterPressure, ack: true });
            await this.setStateAsync('setPoint', { val: data.appliances[0].climateZones[0].setPoint, ack: true });
            await this.setStateAsync('dhwTemperature', { val: data.appliances[0].hotWaterZones[0].dhwTemperature, ack: true });
            //await this.setStateAsync('EnergyConsumption', { val: data.energyConsumption, ack: true });
            await this.setStateAsync('gasCalorificValue', { val: data.appliances[0].gasCalorificValue, ack: true });
            await this.setStateAsync('zoneMode', { val: data.appliances[0].climateZones[0].zoneMode, ack: true });
            await this.setStateAsync('waterPressureToLow', { val: data.appliances[0].waterPressureOK, ack: true });
            //await this.setStateAsync('EnergyDelivered', { val: data.energyDelivered, ack: true });

        } catch (error) {
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
            this.log.debug('checkTokenValidity Status:' + response.statusCode);
            await this.setStateAsync('info.connection', response.statusCode === 200 ? true : false, true);

            await this.sleep(2000)
            return response.statusCode;
        } catch (error) {
            this.log.error(`Token validity check failed: ${error}`);
            return false;
        }
    }

    onMessage(obj) {
        if (obj && obj.command) {
            switch (obj.command) {
                case 'send':
                    this.log.info('Send command');
                    break;
                case 'get':
                    this.log.info('Get command');
                    break;
                default:
                    this.log.warn('Unknown command: ' + obj.command);
            }
        }
    }

    onStateChange(id, state) {
        if (state && !state.ack) {
        }
    }

    onUnload(callback) {
        try {
            this.setState('info.connection', false, true);
            clearInterval(this.interval);
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
