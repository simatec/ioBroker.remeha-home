"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var utils = __toESM(require("@iobroker/adapter-core"));
var import_tools = require("./lib/tools.js");
var import_url = require("url");
var import_got = __toESM(require("@esm2cjs/got"));
var import_tough_cookie = require("tough-cookie");
class RemehaHomeAdapter extends utils.Adapter {
  constructor(options = {}) {
    super({
      ...options,
      name: "remeha-home"
    });
    this.account = "";
    this.pollInterval = 60;
    this.accessToken = null;
    this.refreshToken = null;
    this.csrfToken = "";
    this.codeChallenge = null;
    this.state = "";
    this.postUpdate = false;
    this.getUpdate = false;
    this.password = "";
    this.cookieJar = new import_tough_cookie.CookieJar();
    this.systemLang = "de";
    void this.loadGot();
    this.on("ready", this.onReady.bind(this));
    this.on("unload", this.onUnload.bind(this));
    this.on("stateChange", this.onStateChange.bind(this));
  }
  async onReady() {
    var _a;
    this.log.info("Remeha Home Adapter started.");
    const _language = await this.getForeignObjectsAsync("system.config");
    const systemConfig = _language["system.config"];
    if ((_a = systemConfig == null ? void 0 : systemConfig.common) == null ? void 0 : _a.language) {
      this.systemLang = systemConfig.common.language;
    }
    this.account = this.config.account;
    this.password = this.config.password;
    this.pollInterval = this.config.pollInterval;
    if (isNaN(this.pollInterval) || this.pollInterval < 30) this.pollInterval = 30;
    if (this.pollInterval > 300) this.pollInterval = 300;
    this.subscribeStates("data.roomThermostat.setPoint");
    this.subscribeStates("data.roomThermostat.firePlaceModeActive");
    this.subscribeStates("data.roomThermostat.setZoneMode");
    await this.createDevices();
    await this.schedulePoll();
  }
  async onStateChange(id, state) {
    if (state && !this.getUpdate) {
      if (id === `${this.namespace}.data.roomThermostat.setPoint`) {
        this.postUpdate = true;
        if (!(state == null ? void 0 : state.ack)) {
          await this.setState("data.roomThermostat.setPoint", { val: state == null ? void 0 : state.val, ack: true });
        } else {
          const postData = {
            roomTemperatureSetPoint: state.val
          };
          await this.setValues("setPoint", postData);
        }
      }
      if (id === `${this.namespace}.data.roomThermostat.setZoneMode`) {
        this.postUpdate = true;
        if (!(state == null ? void 0 : state.ack)) {
          await this.setState("data.roomThermostat.setZoneMode", { val: state == null ? void 0 : state.val, ack: true });
        } else {
          let mode = "";
          switch (state.val) {
            case "Scheduling":
              mode = "schedule";
              break;
            case "Manual":
              mode = "manual";
              break;
            case "FrostProtection":
              mode = "anti-frost";
              break;
          }
          const postData = {
            zoneMode: state.val,
            value: mode
          };
          await this.setValues("zoneMode", postData);
        }
      }
      if (id === `${this.namespace}.data.roomThermostat.firePlaceModeActive`) {
        this.postUpdate = true;
        if (!(state == null ? void 0 : state.ack)) {
          await this.setState("data.roomThermostat.firePlaceModeActive", { val: state == null ? void 0 : state.val, ack: true });
        } else {
          const postData = {
            fireplaceModeActive: state.val
          };
          await this.setValues("fireplaceModeActive", postData);
        }
      }
    }
  }
  async onUnload(callback) {
    try {
      await this.setState("info.connection", false, true);
      this.clearInterval(this.interval);
      callback();
    } catch (e) {
      this.log.error(`Error on unload: ${e}`);
      callback();
    }
  }
  async createDevices() {
    const scheduling = await (0, import_tools._translate)("Scheduling", this.systemLang);
    const manual = await (0, import_tools._translate)("Manual", this.systemLang);
    const frostProtection = await (0, import_tools._translate)("FrostProtection", this.systemLang);
    const states = [
      {
        id: "data.roomThermostat.roomTemperature",
        name: "Room Temperature",
        read: true,
        write: false,
        type: "number",
        role: "value.temperature",
        unit: "\xB0C"
      },
      {
        id: "data.dhw.outdoorTemperature",
        name: "Outdoor Temperature",
        read: true,
        write: false,
        type: "number",
        role: "value.temperature",
        unit: "\xB0C"
      },
      {
        id: "data.dhw.waterPressure",
        name: "Water Pressure",
        read: true,
        write: false,
        type: "number",
        role: "value.pressure",
        unit: "bar"
      },
      {
        id: "data.roomThermostat.setPoint",
        name: "Set Point Temperature",
        read: true,
        write: true,
        type: "number",
        role: "level.temperature",
        unit: "\xB0C"
      },
      {
        id: "data.dhw.dhwTemperature",
        name: "DHW Temperature",
        read: true,
        write: false,
        type: "number",
        role: "value.temperature",
        unit: "\xB0C"
      },
      {
        id: "data.dhw.dhwTargetSetpoint",
        name: "DHW Target Setpoint",
        read: true,
        write: false,
        type: "number",
        role: "value.temperature",
        unit: "\xB0C"
      },
      {
        id: "data.dhw.dhwStatus",
        name: "DHW Status",
        read: true,
        write: false,
        type: "string",
        role: "value"
      },
      {
        id: "data.dhw.name",
        name: "DHW Name",
        read: true,
        write: false,
        type: "string",
        role: "value"
      },
      {
        id: "data.dhw.gasCalorificValue",
        name: "Gas Calorific Value",
        read: true,
        write: false,
        type: "number",
        role: "value.power",
        unit: "kWh/m\xB3"
      },
      {
        id: "data.roomThermostat.name",
        name: "Thermostat Name",
        read: true,
        write: false,
        type: "string",
        role: "value"
      },
      {
        id: "data.roomThermostat.setZoneMode",
        name: "Set Zone Mode",
        role: "level.mode.thermostat",
        read: true,
        write: true,
        type: "string",
        states: { Scheduling: scheduling, Manual: manual, FrostProtection: frostProtection }
      },
      {
        id: "data.roomThermostat.currentZoneMode",
        name: "Current Zone Mode",
        role: "level.mode.thermostat",
        read: true,
        write: false,
        type: "string"
      },
      {
        id: "data.dhw.waterPressureOK",
        name: "Water Pressure OK",
        read: true,
        write: false,
        role: "switch",
        type: "boolean"
      },
      {
        id: "data.roomThermostat.firePlaceModeActive",
        name: "Fireplace Mode Active",
        read: true,
        write: true,
        role: "switch",
        type: "boolean"
      },
      {
        id: "data.roomThermostat.nextSetpoint",
        name: "next Setpoint",
        read: true,
        write: false,
        role: "value.temperature",
        type: "number",
        unit: "\xB0C"
      },
      {
        id: "data.roomThermostat.currentScheduleSetPoint",
        name: "current Schedule SetPoint",
        read: false,
        write: false,
        role: "value.temperature",
        type: "number",
        unit: "\xB0C"
      },
      {
        id: "data.roomThermostat.nextSwitchTime",
        name: "next Switch Time",
        read: true,
        write: false,
        role: "value.datetime",
        type: "string"
      },
      {
        id: "data.roomThermostat.activeComfortDemand",
        name: "active Comfort Demand",
        read: true,
        write: false,
        role: "value",
        type: "string"
      },
      {
        id: "info.deviceType",
        name: "Device Type",
        read: true,
        write: false,
        role: "value",
        type: "string"
      },
      {
        id: "info.serialNumber",
        name: "Serial Number",
        read: true,
        write: false,
        role: "value",
        type: "string"
      },
      {
        id: "info.softwareVersion",
        name: "Software Version",
        read: true,
        write: false,
        role: "value",
        type: "string"
      },
      {
        id: "info.hardwareVersion",
        name: "Hardware Version",
        read: true,
        write: false,
        role: "value",
        type: "string"
      },
      {
        id: "info.applianceName",
        name: "Appliance Name",
        read: true,
        write: false,
        role: "value",
        type: "string"
      }
    ];
    for (const state of states) {
      await this.setObjectNotExistsAsync(state.id, {
        type: "state",
        common: {
          name: await (0, import_tools._translate)(state.name, this.systemLang),
          type: state.type || "number",
          role: state.role,
          unit: state.unit || "",
          read: state.read,
          write: state.write,
          states: state.states || void 0
        },
        native: {}
      });
    }
  }
  async schedulePoll() {
    await this.poll();
    this.interval = this.setInterval(() => this.poll(), this.pollInterval * 1e3);
  }
  async poll() {
    try {
      if (this.accessToken === null) {
        await this.resolveExternalData();
      } else if (this.accessToken !== null && await this.checkTokenValidity(this.accessToken) !== 200) {
        await this.refreshAccessToken();
      }
      if (await this.checkTokenValidity(this.accessToken) === 200) {
        await this.updateDevices();
      }
    } catch (error) {
      this.log.error(`Polling error: ${error.message}`);
    }
  }
  loadGot() {
    this.got = import_got.default;
    this.client = this.got.extend({
      prefixUrl: "https://remehalogin.bdrthermea.net",
      timeout: {
        connect: 2e3,
        request: 5e3
      },
      cookieJar: this.cookieJar
    });
  }
  async resolveExternalData() {
    try {
      this.state = await (0, import_tools.randomBytes)(32);
      const codeChallenge = await (0, import_tools.generateRandomToken)(64);
      this.codeChallenge = codeChallenge;
      const codeChallengeSha256 = await (0, import_tools.computeCodeChallenge)(codeChallenge);
      const response = await this.client.get("bdrb2cprod.onmicrosoft.com/oauth2/v2.0/authorize?", {
        searchParams: {
          response_type: "code",
          client_id: "6ce007c6-0628-419e-88f4-bee2e6418eec",
          redirect_uri: "com.b2c.remehaapp://login-callback",
          scope: "openid https://bdrb2cprod.onmicrosoft.com/iotdevice/user_impersonation offline_access",
          state: this.state,
          code_challenge: codeChallengeSha256,
          code_challenge_method: "S256",
          p: "B2C_1A_RPSignUpSignInNewRoomV3.1",
          brand: "remeha",
          lang: "en",
          nonce: "defaultNonce",
          prompt: "login",
          signUp: "False"
        },
        followRedirect: true
      });
      this.log.debug(`Get Auth: ${response.statusCode === 200 ? "OK" : "failed"}`);
      let csrfTokenCookie;
      const cookies = response.headers["set-cookie"];
      if (cookies) {
        csrfTokenCookie = cookies.find(
          (cookie) => cookie.startsWith("x-ms-cpim-csrf=") && cookie.includes("domain=remehalogin.bdrthermea.net")
        );
        if (csrfTokenCookie) {
          this.csrfToken = csrfTokenCookie.split(";")[0].replace("x-ms-cpim-csrf=", "").replace(/;$/, "");
        } else {
          throw new Error("CSRF-Token not found in response headers.");
        }
      }
      const requestId = response.headers["x-request-id"];
      const statePropertiesJson = `{"TID":"${requestId}"}`;
      const stateProperties = Buffer.from(statePropertiesJson).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      const authorizationCode = await this.login(stateProperties, this.csrfToken);
      if (!authorizationCode) throw new Error("Authorization code is missing.");
      await this.fetchAccessToken(authorizationCode);
    } catch (error) {
      this.log.error(`Error resolving external data: ${error.message}`);
    }
  }
  async login(stateProperties, csrfToken) {
    try {
      const response = await this.client.post(
        "bdrb2cprod.onmicrosoft.com/B2C_1A_RPSignUpSignInNewRoomv3.1/SelfAsserted",
        {
          searchParams: {
            tx: `StateProperties=${stateProperties}`,
            p: "B2C_1A_RPSignUpSignInNewRoomv3.1"
          },
          form: {
            request_type: "RESPONSE",
            signInName: this.account,
            password: this.password
          },
          headers: {
            "x-csrf-token": csrfToken
          },
          followRedirect: true
        }
      );
      this.log.debug(`Post Login Status: ${response.statusCode === 200 ? "OK" : "failed"}`);
    } catch (error) {
      this.log.error(`Error during login: ${error.message}`);
      if (error.response) {
        this.log.error(`Response status: ${error.response.status}`);
      }
      throw error;
    }
    try {
      const response = await this.client.get(
        "bdrb2cprod.onmicrosoft.com/B2C_1A_RPSignUpSignInNewRoomv3.1/api/CombinedSigninAndSignup/confirmed",
        {
          searchParams: {
            rememberMe: "false",
            csrf_token: csrfToken,
            tx: `StateProperties=${stateProperties}`,
            p: "B2C_1A_RPSignUpSignInNewRoomv3.1"
          },
          followRedirect: false
        }
      );
      this.log.debug(`Get Login Status: ${response.statusCode === 302 ? "OK" : "failed"}`);
      const parsedCallbackUrl = new import_url.URL(response.headers.location);
      if (parsedCallbackUrl) {
        const queryStringDict = parsedCallbackUrl.searchParams;
        const code = queryStringDict.get("code");
        if (code) {
          return code;
        } else {
          this.log.debug("Authorization code not found");
        }
      } else {
        this.log.debug("No redirect URL found in response headers.");
      }
      this.log.debug("Authorization code not found in redirect URL.");
      return null;
    } catch (error) {
      this.log.error(`Error get code: ${error}`);
      if (error.response) {
        this.log.error(`Response error Status: ${error.response}`);
      }
      throw error;
    }
  }
  async fetchAccessToken(code) {
    try {
      const grantParams = {
        grant_type: "authorization_code",
        code,
        redirect_uri: "com.b2c.remehaapp://login-callback",
        code_verifier: this.codeChallenge,
        client_id: "6ce007c6-0628-419e-88f4-bee2e6418eec"
      };
      const response = await this.client.post("bdrb2cprod.onmicrosoft.com/oauth2/v2.0/token", {
        searchParams: {
          p: "B2C_1A_RPSignUpSignInNewRoomV3.1"
        },
        form: grantParams,
        followRedirect: true,
        responseType: "json"
      });
      this.log.debug(`Get Accesstoken Status: ${response.statusCode === 200 ? "OK" : "failed"}`);
      const data = response.body;
      this.accessToken = data.access_token;
      this.refreshToken = data.refresh_token;
      return this.accessToken;
    } catch (error) {
      this.log.error(`Error fetching access token: ${error}`);
      throw error;
    }
  }
  async refreshAccessToken() {
    try {
      const grantParams = {
        grant_type: "refresh_token",
        refresh_token: this.refreshToken,
        client_id: "6ce007c6-0628-419e-88f4-bee2e6418eec"
      };
      const response = await this.client.post("bdrb2cprod.onmicrosoft.com/oauth2/v2.0/token", {
        searchParams: {
          p: "B2C_1A_RPSignUpSignInNewRoomV3.1"
        },
        form: grantParams,
        followRedirect: true,
        responseType: "json"
      });
      this.log.debug(`Get Refreshtoken Status: ${response.statusCode === 200 ? "OK" : "failed"}`);
      const data = response.body;
      this.accessToken = data.access_token;
    } catch (error) {
      this.log.error(`Error refreshing access token: ${error}`);
      throw error;
    }
  }
  async updateDevices() {
    try {
      const response = await this.got.get("https://api.bdrthermea.net/Mobile/api/homes/dashboard", {
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          "Ocp-Apim-Subscription-Key": "df605c5470d846fc91e848b1cc653ddf",
          "x-csrf-token": this.csrfToken
        }
      });
      this.log.debug(`Get Update Status: ${response.statusCode === 200 ? "OK" : "failed"}`);
      const data = JSON.parse(response.body);
      const _zoneMode = data.appliances[0].climateZones[0].zoneMode;
      const _zoneModeTranslate = await (0, import_tools._translate)(_zoneMode, this.systemLang);
      await this.setState("data.roomThermostat.roomTemperature", {
        val: data.appliances[0].climateZones[0].roomTemperature,
        ack: true
      });
      await this.setState("data.dhw.outdoorTemperature", {
        val: data.appliances[0].outdoorTemperature,
        ack: true
      });
      await this.setState("data.dhw.waterPressure", {
        val: data.appliances[0].waterPressure,
        ack: true
      });
      await this.setState("data.dhw.dhwTemperature", {
        val: data.appliances[0].hotWaterZones[0].dhwTemperature,
        ack: true
      });
      await this.setState("data.dhw.dhwTargetSetpoint", {
        val: data.appliances[0].hotWaterZones[0].targetSetpoint,
        ack: true
      });
      await this.setState("data.dhw.dhwStatus", {
        val: data.appliances[0].hotWaterZones[0].dhwStatus,
        ack: true
      });
      await this.setState("data.dhw.name", {
        val: data.appliances[0].hotWaterZones[0].name,
        ack: true
      });
      await this.setState("data.dhw.gasCalorificValue", {
        val: data.appliances[0].gasCalorificValue,
        ack: true
      });
      await this.setState("data.roomThermostat.currentZoneMode", {
        val: _zoneModeTranslate,
        ack: true
      });
      await this.setState("data.dhw.waterPressureOK", {
        val: data.appliances[0].waterPressureOK,
        ack: true
      });
      await this.setState("data.roomThermostat.name", {
        val: data.appliances[0].climateZones[0].name,
        ack: true
      });
      await this.setState("data.roomThermostat.nextSetpoint", {
        val: data.appliances[0].climateZones[0].nextSetpoint,
        ack: true
      });
      await this.setState("data.roomThermostat.currentScheduleSetPoint", {
        val: data.appliances[0].climateZones[0].currentScheduleSetPoint,
        ack: true
      });
      await this.setState("data.roomThermostat.activeComfortDemand", {
        val: data.appliances[0].climateZones[0].activeComfortDemand,
        ack: true
      });
      await this.setState("data.roomThermostat.nextSwitchTime", {
        val: data.appliances[0].climateZones[0].nextSwitchTime,
        ack: true
      });
      this.log.debug(`postUpdate: ${this.postUpdate}`);
      this.getUpdate = true;
      if (_zoneMode !== "TemporaryOverride" && !this.postUpdate) {
        const stateZoneMode = await this.getStateAsync("data.roomThermostat.setZoneMode");
        if ((stateZoneMode == null ? void 0 : stateZoneMode.val) !== _zoneMode) {
          await this.setState("data.roomThermostat.setZoneMode", {
            val: _zoneMode,
            ack: true
          });
          this.log.debug(`new ZoneMode is: ${_zoneMode}`);
        }
      }
      const stateSetPoint = await this.getStateAsync("data.roomThermostat.setPoint");
      if ((stateSetPoint == null ? void 0 : stateSetPoint.val) !== data.appliances[0].climateZones[0].setPoint && !this.postUpdate) {
        await this.setState("data.roomThermostat.setPoint", {
          val: data.appliances[0].climateZones[0].setPoint,
          ack: true
        });
        this.log.debug(`new setPoint is: ${data.appliances[0].climateZones[0].setPoint} \xB0C`);
      }
      const stateFirePlace = await this.getStateAsync("data.roomThermostat.firePlaceModeActive");
      if ((stateFirePlace == null ? void 0 : stateFirePlace.val) !== data.appliances[0].climateZones[0].firePlaceModeActive && !this.postUpdate) {
        await this.setState("data.roomThermostat.firePlaceModeActive", {
          val: data.appliances[0].climateZones[0].firePlaceModeActive,
          ack: true
        });
        this.log.debug(`new firePlaceMode is: ${data.appliances[0].climateZones[0].firePlaceModeActive}`);
      }
      await this.delay(1e3);
      this.getUpdate = false;
      const appliance = await this.got.get(
        `https://api.bdrthermea.net/Mobile/api/appliances/${data == null ? void 0 : data.appliances[0].applianceId}/technicaldetails`,
        {
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
            "Ocp-Apim-Subscription-Key": "df605c5470d846fc91e848b1cc653ddf",
            "x-csrf-token": this.csrfToken
          }
        }
      );
      this.log.debug(`Get Device Info Status: ${appliance.statusCode === 200 ? "OK" : "failed"}`);
      const applianceInfo = JSON.parse(appliance.body);
      await this.setState("info.applianceName", {
        val: applianceInfo.applianceName,
        ack: true
      });
      await this.setState("info.deviceType", {
        val: applianceInfo.internetConnectedGateways[0].deviceTypeName,
        ack: true
      });
      await this.setState("info.serialNumber", {
        val: applianceInfo.internetConnectedGateways[0].serialNumber,
        ack: true
      });
      await this.setState("info.softwareVersion", {
        val: applianceInfo.internetConnectedGateways[0].softwareVersion,
        ack: true
      });
      await this.setState("info.hardwareVersion", {
        val: applianceInfo.internetConnectedGateways[0].hardwareVersion,
        ack: true
      });
    } catch (error) {
      this.log.error(`Error updating devices: ${error}`);
    }
  }
  async checkTokenValidity(token) {
    try {
      const response = await this.got.get("https://api.bdrthermea.net/Mobile/api/homes/dashboard", {
        headers: {
          Authorization: `Bearer ${token}`,
          "Ocp-Apim-Subscription-Key": "df605c5470d846fc91e848b1cc653ddf",
          "x-csrf-token": this.csrfToken
        }
      });
      this.log.debug(`Get checkTokenValidity Status: ${response.statusCode === 200 ? "OK" : "failed"}`);
      await this.setState("info.connection", response.statusCode === 200 ? true : false, true);
      await this.delay(500);
      return response.statusCode;
    } catch (error) {
      this.log.debug(`Token validity check failed. An attempt is being made to obtain a new token: ${error}`);
      await this.setState("info.connection", false, true);
      return false;
    }
  }
  async setValues(type, postData) {
    if (this.accessToken === null) {
      await this.resolveExternalData();
    } else if (this.accessToken !== null && await this.checkTokenValidity(this.accessToken) !== 200) {
      await this.refreshAccessToken();
    }
    if (await this.checkTokenValidity(this.accessToken) === 200) {
      const headers = {
        Authorization: `Bearer ${this.accessToken}`,
        "Ocp-Apim-Subscription-Key": "df605c5470d846fc91e848b1cc653ddf",
        "x-csrf-token": this.csrfToken
      };
      try {
        const response = await this.got.get("https://api.bdrthermea.net/Mobile/api/homes/dashboard", {
          headers
        });
        const responseJson = JSON.parse(response.body);
        const climateZoneId = responseJson.appliances[0].climateZones[0].climateZoneId;
        const valueSetpoint = responseJson.appliances[0].climateZones[0].setPoint;
        const valueFireplaceMode = responseJson.appliances[0].climateZones[0].firePlaceModeActive;
        const valueZoneMode = responseJson.appliances[0].climateZones[0].zoneMode;
        const valueProgNumber = responseJson.appliances[0].climateZones[0].activeHeatingClimateTimeProgramNumber;
        await this.delay(1e3);
        switch (type) {
          case "setPoint":
            if (valueZoneMode !== "Manual" || valueSetpoint !== (postData == null ? void 0 : postData.roomTemperatureSetPoint)) {
              try {
                const postResponse = await this.got.post(
                  `https://api.bdrthermea.net/Mobile/api/climate-zones/${climateZoneId}/modes/${valueZoneMode !== "Manual" ? "temporary-override" : "manual"}`,
                  {
                    headers,
                    json: postData,
                    responseType: "json"
                  }
                );
                this.log.debug(`Post SetPoint: ${postResponse.statusCode === 200 ? "OK" : "failed"}`);
              } catch (postError) {
                this.log.error(`Error making POST request SetPoint: ${postError}`);
              }
            } else {
              this.log.debug("setpoint noChange");
            }
            break;
          case "fireplaceModeActive":
            if (valueFireplaceMode !== (postData == null ? void 0 : postData.firePlaceModeActive)) {
              try {
                const postResponse = await this.got.post(
                  `https://api.bdrthermea.net/Mobile/api/climate-zones/${climateZoneId}/modes/fireplacemode`,
                  {
                    headers,
                    json: postData,
                    responseType: "json"
                  }
                );
                this.log.debug(
                  `Post fireplacemode: ${postResponse.statusCode === 200 ? "OK" : "failed"}`
                );
              } catch (postError) {
                this.log.error(`Error making POST request for fireplacemode: ${postError}`);
              }
            } else {
              this.log.debug("fireplaceMode noChange");
            }
            break;
          case "zoneMode":
            if (valueZoneMode !== (postData == null ? void 0 : postData.zoneMode)) {
              const jsonData = (postData == null ? void 0 : postData.zoneMode) === "Scheduling" ? { heatingProgramId: valueProgNumber } : (postData == null ? void 0 : postData.zoneMode) === "Manual" ? { roomTemperatureSetPoint: valueSetpoint } : null;
              try {
                const postResponse = await this.got.post(
                  `https://api.bdrthermea.net/Mobile/api/climate-zones/${climateZoneId}/modes/${postData == null ? void 0 : postData.value}`,
                  {
                    headers,
                    json: jsonData,
                    responseType: "json"
                  }
                );
                this.log.debug(`Post ZoneMode: ${postResponse.statusCode === 200 ? "OK" : "failed"}`);
              } catch (postError) {
                this.log.error(`Error making POST request for zoneMode: ${postError}`);
              }
            } else {
              this.log.debug("zoneMode noChange");
            }
            break;
        }
        await this.delay(5e3);
        this.postUpdate = false;
        await this.updateDevices();
      } catch (getError) {
        this.postUpdate = false;
        this.log.error(`Error making GET request: ${getError}`);
      }
    }
  }
}
if (require.main !== module) {
  module.exports = (options) => new RemehaHomeAdapter(options);
} else {
  (() => new RemehaHomeAdapter())();
}
//# sourceMappingURL=main.js.map
