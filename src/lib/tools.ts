import crypto from 'crypto';

export async function _translate(word: string, systemLang: string): Promise<string> {
    return new Promise(resolve => {
        void (async () => {
            const translations = await import(`../../admin/i18n/${systemLang ? systemLang : 'en'}/translations.json`);
            if (translations[word]) {
                resolve(translations[word]);
            } else {
                console.warn(`Please translate in translations.json: ${word}`);
                resolve(word);
            }
        })();
    });
}

export async function generateRandomToken(length: number): Promise<string> {
    return new Promise(resolve => {
        const randomToken = crypto.randomBytes(length).toString('base64url');
        resolve(randomToken);
    });
}

export async function computeCodeChallenge(token: string): Promise<string | null> {
    return new Promise(resolve => {
        const hash = crypto.createHash('sha256');
        hash.update(token);
        const digest = hash.digest();

        const base64Url = digest.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

        resolve(base64Url);
    });
}

export async function randomBytes(length: number): Promise<string | null> {
    return new Promise(resolve => {
        const _randomBytes = crypto.randomBytes(length).toString('base64url');
        resolve(_randomBytes);
    });
}
