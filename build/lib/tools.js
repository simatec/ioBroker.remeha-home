"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
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
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);
var tools_exports = {};
__export(tools_exports, {
  _translate: () => _translate,
  computeCodeChallenge: () => computeCodeChallenge,
  generateRandomToken: () => generateRandomToken,
  randomBytes: () => randomBytes
});
module.exports = __toCommonJS(tools_exports);
var import_crypto = __toESM(require("crypto"));
async function _translate(word, systemLang) {
  return new Promise(async (resolve) => {
    const translations = await Promise.resolve().then(() => __toESM(require(`../../admin/i18n/${systemLang ? systemLang : "en"}/translations.json`)));
    if (translations[word]) {
      resolve(translations[word]);
    } else {
      console.warn(`Please translate in translations.json: ${word}`);
      resolve(word);
    }
  });
}
async function generateRandomToken(length) {
  return new Promise((resolve) => {
    const randomToken = import_crypto.default.randomBytes(length).toString("base64url");
    resolve(randomToken);
  });
}
async function computeCodeChallenge(token) {
  return new Promise((resolve) => {
    const hash = import_crypto.default.createHash("sha256");
    hash.update(token);
    const digest = hash.digest();
    const base64Url = digest.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    resolve(base64Url);
  });
}
async function randomBytes(length) {
  return new Promise((resolve) => {
    const _randomBytes = import_crypto.default.randomBytes(length).toString("base64url");
    resolve(_randomBytes);
  });
}
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  _translate,
  computeCodeChallenge,
  generateRandomToken,
  randomBytes
});
//# sourceMappingURL=tools.js.map
