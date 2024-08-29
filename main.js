'use strict';

const utils = require('@iobroker/adapter-core');
const axios = require('axios');
const crypto = require('crypto');
const qs = require('qs');
const { URL, URLSearchParams } = require('url');

class RemehaHomeAdapter extends utils.Adapter {
    constructor(options) {
        super({ ...options, name: 'remeha-home' });

        this.account = '';
        this.password = '';
        this.pollInterval = 600;
        this.accessToken = null;
        this.refreshToken = null;
        this.csrfToken = null;
        this.codeVerifier = crypto.randomBytes(32).toString('hex');
        this.state = '';

        this.onReady = this.onReady.bind(this);
        this.onMessage = this.onMessage.bind(this);
        this.onStateChange = this.onStateChange.bind(this);
        this.onUnload = this.onUnload.bind(this);

        this.on('ready', this.onReady);
        this.on('message', this.onMessage);
        this.on('stateChange', this.onStateChange);
        this.on('unload', this.onUnload);
    }

    async onReady() {
        this.log.info('Remeha Home Adapter started.');
        this.account = this.config.account;
        this.password = this.config.password;
        //this.pollInterval = parseInt(this.config.pollInterval, 10);

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
            if (!this.accessToken || !await this.checkTokenValidity(this.accessToken)) {
                await this.resolveExternalData();
            }
            await this.updateDevices();
        } catch (error) {
            this.log.error(`Polling error: ${error.message}`);
        }
    }

    async generateRandomState() {
        const base64 = crypto.randomBytes(32).toString('base64');
        return base64
            .replace(/\+/g, '-') // Ersetze '+' durch '-'
            .replace(/\//g, '_') // Ersetze '/' durch '_'
            .replace(/=+$/, ''); // Entferne Padding-Zeichen '='
    }

    async resolveExternalData() {
        try {
            this.state = await this.generateRandomState();
            //this.state = crypto.randomBytes(32).toString('base64url');
            //const codeChallenge = await this.generateCodeChallenge(this.codeVerifier);
            const codeChallenge = await this.generateRandomToken(64);
            const codeChallengeSha256 = await this.computeCodeChallenge(codeChallenge);

            this.log.debug(`Using state: ${this.state}`);
            this.log.debug(`Code challenge: ${codeChallenge}`);

            // Schritt 1: CSRF-Token und andere Daten abrufen
            const response = await axios.get('https://remehalogin.bdrthermea.net/bdrb2cprod.onmicrosoft.com/oauth2/v2.0/authorize', {
                params: {
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
                //maxRedirects: 0 // Entsprechend allow_redirects=False
            });

            //this.log.debug('Initial response headers: ' + response.headers);
            let csrfTokenCookie;
            const cookies = response.headers['set-cookie'];
            if (cookies) {

                csrfTokenCookie = cookies.find(cookie => cookie.startsWith('x-ms-cpim-csrf=') && cookie.includes('domain=remehalogin.bdrthermea.net'));

                if (csrfTokenCookie) {
                    this.csrfToken = csrfTokenCookie.split('=')[1].split(';')[0];
                    //this.log.debug(`CSRF-Token extracted: ${this.csrfToken}`);
                } else {
                    throw new Error('CSRF-Token not found in response headers.');
                }

            }

            // Generiere state_properties basierend auf dem aktuellen Zustand

            const statePropertiesJson = JSON.stringify({ "state": this.state });
            const statePropertiesBase64 = Buffer.from(statePropertiesJson).toString('base64');
            const stateProperties = statePropertiesBase64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

            this.log.debug(`stateProperties: ${stateProperties}`);

            // Schritt 2: Login durchführen
            const authorizationCode = await this.login(stateProperties, this.csrfToken);
            this.log.debug(`authorizationCode: ${authorizationCode}`)
            // Schritt 3: Zugriffstoken mit Autorisierungscode abrufen
            if (!authorizationCode) throw new Error('Authorization code is missing.');

            await this.fetchAccessToken(authorizationCode);
        } catch (error) {
            this.log.error(`Error resolving external data: ${error.message}`);
        }
    }


    async login(stateProperties, csrfToken) {
        try {
            this.log.debug(`Attempting login with stateProperties: ${stateProperties}`);
            this.log.debug(`CSRF-Token: ${csrfToken}`);

            // Daten im application/x-www-form-urlencoded Format vorbereiten
            const postData = qs.stringify({
                request_type: 'RESPONSE',
                signInName: this.account,
                password: this.password
            });

            // POST-Anfrage an die Login-URL
            const response = await axios.post(
                'https://remehalogin.bdrthermea.net/bdrb2cprod.onmicrosoft.com/B2C_1A_RPSignUpSignInNewRoomv3.1/SelfAsserted',
                {
                    request_type: 'RESPONSE',
                    signInName: this.account,
                    password: this.password
                },
                {
                    params: {
                        tx: `StateProperties=${stateProperties}`,
                        p: 'B2C_1A_RPSignUpSignInNewRoomv3.1'
                    },
                    headers: {
                        'x-csrf-token': csrfToken,
                        //'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    maxRedirects: 0 // Entsprechend allow_redirects=False
                }
            );

            // Erweiterte Protokollierung für Antwortdetails
            this.log.debug('Login response status:' + response.status);
            //this.log.debug('Login response headers:'+ response.headers);
            //this.log.debug('Login response data:'+ response.data);

        } catch (error) {
            this.log.error('Error during login:' + error.message);
            if (error.response) {
                this.log.error('Response status:' + error.response.status);
                //this.log.error('Response headers:'+ error.response.headers);
                //this.log.error('Response data:' + error.response.data);
            }
            throw error;
        }
        try {
            const response1 = await axios.get(
                "https://remehalogin.bdrthermea.net/bdrb2cprod.onmicrosoft.com/B2C_1A_RPSignUpSignInNewRoomv3.1/api/CombinedSigninAndSignup/confirmed",
                {
                    params: {
                        "rememberMe": "false",
                        "csrf_token": csrfToken,
                        "tx": `StateProperties=${stateProperties}`,
                        "p": "B2C_1A_RPSignUpSignInNewRoomv3.1",
                        invalidParam: 'true',
                    },
                    maxRedirects: 0, // Verhindert automatische Weiterleitungen
                }
            );
            this.log.debug('Login response1 status:' + response1.status);
            //this.log.debug('Login response1 headers:' + response1.headers);

            /*
            const locationHeader = response1.headers['location'];
            if (locationHeader) {
                this.log.debug('Redirect URL:', locationHeader);
                const url = new URL(locationHeader);
                const code = url.searchParams.get('code');
                
                */
            const parsedCallbackUrl = new URL(response1.headers.location);
            if (parsedCallbackUrl) {
                const queryStringDict = parsedCallbackUrl.searchParams;
                const code = queryStringDict.get('code');
                if (code) {
                    this.log.debug('Authorization code extracted:' + code);
                    return code;
                } else {
                    this.log.debug('Authorization code not found');

                }
            } else {
                this.log.debug('No redirect URL found in response headers.');
            }

            // Falls der Autorisierungscode nicht gefunden wird
            //this.log.debug('Authorization code not found in redirect URL.');
            //return null;

        } catch (error) {
            this.log.error('Error get code:' + error.message);
            if (error.response1) {
                this.log.error('Response status:' + error.response1.status);
                this.log.error('Response headers:' + error.response1.headers);
                //this.log.error('Response data:' + error.response.data);
            }
            throw error;
        }
    }


    // Hilfsmethode zum Extrahieren des Autorisierungscodes
    extractAuthorizationCode(response) {
        const locationHeader = response.headers['location'];
        if (locationHeader && locationHeader.includes('code=')) {
            const url = new URL(locationHeader);
            const code = url.searchParams.get('code');
            if (code) {
                this.log.debug('Authorization code extracted:', code);
                return code;
            }
        }
        this.log.debug('Authorization code not found in redirect URL.');
        return null;
    }


    // Schritt 1: Generiere einen zufälligen, URL-sicheren Token
    async generateRandomToken(length) {
        return crypto.randomBytes(length).toString('base64url');
    }

    // Schritt 2: Berechne den SHA-256-Hash des Tokens
    async computeCodeChallenge(token) {
        const hash = crypto.createHash('sha256');
        hash.update(token);
        const digest = hash.digest();

        // Schritt 3: Kodieren des Hashes in Base64 (URL-sicher)
        const base64Url = digest.toString('base64')
            .replace(/\+/g, '-')  // Ersetze '+' durch '-'
            .replace(/\//g, '_')  // Ersetze '/' durch '_'
            .replace(/=+$/, '');  // Entferne Padding-Zeichen '='

        return base64Url;
    }
    async generateCodeChallenge(codeVerifier) {
        const hash = crypto.createHash('sha256');
        hash.update(codeVerifier);
        const codeChallenge = hash.digest('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        return codeChallenge;
    }

    async fetchAccessToken(code) {
        try {
            const tokenUrl = 'https://remehalogin.bdrthermea.net/bdrb2cprod.onmicrosoft.com/oauth2/v2.0/token';
            const tokenParams = {
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: 'com.b2c.remehaapp://login-callback',
                client_id: '6ce007c6-0628-419e-88f4-bee2e6418eec',
                code_verifier: this.codeVerifier
            };

            const response = await axios.post(tokenUrl, qs.stringify(tokenParams), {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });

            this.accessToken = response.data.access_token;
            this.refreshToken = response.data.refresh_token;
            this.log.debug('Access Token:', this.accessToken);
            return this.accessToken;
        } catch (error) {
            this.log.error('Error fetching access token:', error.response ? error.response.data : error.message);
            throw error;
        }
    }


    async refreshAccessToken() {
        try {
            const response = await axios.post('https://remehalogin.bdrthermea.net/bdrb2cprod.onmicrosoft.com/oauth2/v2.0/token', qs.stringify({
                grant_type: 'refresh_token',
                refresh_token: this.refreshToken,
                client_id: '6ce007c6-0628-419e-88f4-bee2e6418eec'
            }), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            });

            this.accessToken = response.data.access_token;
            this.log.debug('Refreshed Access Token:', this.accessToken);
        } catch (error) {
            this.log.error('Error refreshing access token:', error.response ? error.response.data : error.message);
            throw error;
        }
    }

    async updateDevices() {
        try {
            if (!this.accessToken || !await this.checkTokenValidity(this.accessToken)) {
                await this.fetchAccessToken(); // oder refreshAccessToken()
            }

            const response = await axios.get('https://api.bdrthermea.net/Mobile/api/homes/dashboard', {
                headers: {
                    'Authorization': `Bearer ${this.accessToken}`,
                    'Ocp-Apim-Subscription-Key': 'df605c5470d846fc91e848b1cc653ddf',
                    'x-csrf-token': this.csrfToken
                }
            });

            const data = response.data;

            await this.setStateAsync('roomTemperature', { val: data.roomTemperature, ack: true });
            await this.setStateAsync('outdoorTemperature', { val: data.outdoorTemperature, ack: true });
            await this.setStateAsync('waterPressure', { val: data.waterPressure, ack: true });
            await this.setStateAsync('setPoint', { val: data.setPoint, ack: true });
            await this.setStateAsync('dhwTemperature', { val: data.dhwTemperature, ack: true });
            await this.setStateAsync('EnergyConsumption', { val: data.energyConsumption, ack: true });
            await this.setStateAsync('gasCalorificValue', { val: data.gasCalorificValue, ack: true });
            await this.setStateAsync('zoneMode', { val: data.zoneMode, ack: true });
            await this.setStateAsync('waterPressureToLow', { val: data.waterPressureToLow, ack: true });
            await this.setStateAsync('EnergyDelivered', { val: data.energyDelivered, ack: true });
        } catch (error) {
            this.log.error(`Error updating devices: ${error.response ? error.response.data : error.message}`);
        }
    }

    async checkTokenValidity(token) {
        try {
            const response = await axios.get('https://api.bdrthermea.net/Mobile/api/homes/dashboard', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Ocp-Apim-Subscription-Key': 'df605c5470d846fc91e848b1cc653ddf',
                    'x-csrf-token': this.csrfToken
                }
            });
            return response.status === 200;
        } catch (error) {
            this.log.error(`Token validity check failed: ${error.response ? error.response.data : error.message}`);
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
            // Hier können Sie Logik zur Behandlung von Statusänderungen hinzufügen
        }
    }

    onUnload(callback) {
        try {
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
