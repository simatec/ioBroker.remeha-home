const crypto = require('crypto');

async function _translate(word, systemLang) {
    return new Promise(async (resolve) => {
        const translations = require(`../admin/i18n/${systemLang ? systemLang : 'en'}/translations.json`);

        if (translations[word]) {
            resolve(translations[word]);
        } else {
            console.warn(`Please translate in translations.json: ${word}`);
            resolve(word);
        }
    });
}

async function generateRandomToken(length) {
    return new Promise(async (resolve) => {
        const randomToken = crypto.randomBytes(length).toString('base64url');
        resolve(randomToken);
    });
}

async function computeCodeChallenge(token) {
    return new Promise(async (resolve) => {
        const hash = crypto.createHash('sha256');
        hash.update(token);
        const digest = hash.digest();

        const base64Url = digest.toString('base64')
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');

        resolve(base64Url);
    });
}

async function randomBytes(length) {
    return new Promise(async (resolve) => {
        const _randomBytes = crypto.randomBytes(length).toString('base64url');
        resolve(_randomBytes);
    });
}

module.exports = {
    _translate,
    generateRandomToken,
    computeCodeChallenge,
    randomBytes,
};