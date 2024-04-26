var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
const encoder = new TextEncoder();
const decoder = new TextDecoder();
function buf(input) {
    if (typeof input === 'string') {
        return encoder.encode(input);
    }
    return decoder.decode(input);
}
function checkRsaKeyAlgorithm(algorithm) {
    if (typeof algorithm.modulusLength !== 'number' || algorithm.modulusLength < 2048) {
        throw new OperationProcessingError(`${algorithm.name} modulusLength must be at least 2048 bits`);
    }
}
function subtleAlgorithm(key) {
    switch (key.algorithm.name) {
        case 'ECDSA':
            return { name: key.algorithm.name, hash: 'SHA-256' };
        case 'RSA-PSS':
            checkRsaKeyAlgorithm(key.algorithm);
            return {
                name: key.algorithm.name,
                saltLength: 256 >> 3,
            };
        case 'RSASSA-PKCS1-v1_5':
            checkRsaKeyAlgorithm(key.algorithm);
            return { name: key.algorithm.name };
        case 'Ed25519':
            return { name: key.algorithm.name };
    }
    throw new UnsupportedOperationError();
}
function jwt(header, claimsSet, key) {
    return __awaiter(this, void 0, void 0, function* () {
        if (key.usages.includes('sign') === false) {
            throw new TypeError('private CryptoKey instances used for signing assertions must include "sign" in their "usages"');
        }
        const input = `${b64u(buf(JSON.stringify(header)))}.${b64u(buf(JSON.stringify(claimsSet)))}`;
        const signature = b64u(yield crypto.subtle.sign(subtleAlgorithm(key), key, buf(input)));
        return `${input}.${signature}`;
    });
}
const CHUNK_SIZE = 0x8000;
function encodeBase64Url(input) {
    if (input instanceof ArrayBuffer) {
        input = new Uint8Array(input);
    }
    const arr = [];
    for (let i = 0; i < input.byteLength; i += CHUNK_SIZE) {
        arr.push(String.fromCharCode.apply(null, input.subarray(i, i + CHUNK_SIZE)));
    }
    return btoa(arr.join('')).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64u(input) {
    return encodeBase64Url(input);
}
function randomBytes() {
    return b64u(crypto.getRandomValues(new Uint8Array(32)));
}
class UnsupportedOperationError extends Error {
    constructor(message) {
        var _a;
        super(message !== null && message !== void 0 ? message : 'operation not supported');
        this.name = this.constructor.name;
        (_a = Error.captureStackTrace) === null || _a === void 0 ? void 0 : _a.call(Error, this, this.constructor);
    }
}
class OperationProcessingError extends Error {
    constructor(message) {
        var _a;
        super(message);
        this.name = this.constructor.name;
        (_a = Error.captureStackTrace) === null || _a === void 0 ? void 0 : _a.call(Error, this, this.constructor);
    }
}
function psAlg(key) {
    switch (key.algorithm.hash.name) {
        case 'SHA-256':
            return 'PS256';
        default:
            throw new UnsupportedOperationError('unsupported RsaHashedKeyAlgorithm hash name');
    }
}
function rsAlg(key) {
    switch (key.algorithm.hash.name) {
        case 'SHA-256':
            return 'RS256';
        default:
            throw new UnsupportedOperationError('unsupported RsaHashedKeyAlgorithm hash name');
    }
}
function esAlg(key) {
    switch (key.algorithm.namedCurve) {
        case 'P-256':
            return 'ES256';
        default:
            throw new UnsupportedOperationError('unsupported EcKeyAlgorithm namedCurve');
    }
}
function determineJWSAlgorithm(key) {
    switch (key.algorithm.name) {
        case 'RSA-PSS':
            return psAlg(key);
        case 'RSASSA-PKCS1-v1_5':
            return rsAlg(key);
        case 'ECDSA':
            return esAlg(key);
        case 'Ed25519':
            return 'EdDSA';
        default:
            throw new UnsupportedOperationError('unsupported CryptoKey algorithm name');
    }
}
function isCryptoKey(key) {
    return key instanceof CryptoKey;
}
function isPrivateKey(key) {
    return isCryptoKey(key) && key.type === 'private';
}
function isPublicKey(key) {
    return isCryptoKey(key) && key.type === 'public';
}
function epochTime() {
    return Math.floor(Date.now() / 1000);
}
export default function DPoP(keypair, htu, htm, nonce, accessToken, additional) {
    return __awaiter(this, void 0, void 0, function* () {
        const privateKey = keypair === null || keypair === void 0 ? void 0 : keypair.privateKey;
        const publicKey = keypair === null || keypair === void 0 ? void 0 : keypair.publicKey;
        if (!isPrivateKey(privateKey)) {
            throw new TypeError('"keypair.privateKey" must be a private CryptoKey');
        }
        if (!isPublicKey(publicKey)) {
            throw new TypeError('"keypair.publicKey" must be a public CryptoKey');
        }
        if (publicKey.extractable !== true) {
            throw new TypeError('"keypair.publicKey.extractable" must be true');
        }
        if (typeof htu !== 'string') {
            throw new TypeError('"htu" must be a string');
        }
        if (typeof htm !== 'string') {
            throw new TypeError('"htm" must be a string');
        }
        if (nonce !== undefined && typeof nonce !== 'string') {
            throw new TypeError('"nonce" must be a string or undefined');
        }
        if (accessToken !== undefined && typeof accessToken !== 'string') {
            throw new TypeError('"accessToken" must be a string or undefined');
        }
        if (additional !== undefined &&
            (typeof additional !== 'object' || typeof additional === null || Array.isArray(additional))) {
            throw new TypeError('"additional" must be an object');
        }
        return jwt({
            alg: determineJWSAlgorithm(privateKey),
            typ: 'dpop+jwt',
            jwk: yield publicJwk(publicKey),
        }, Object.assign(Object.assign({}, additional), { iat: epochTime(), jti: randomBytes(), htm,
            nonce,
            htu, ath: accessToken ? b64u(yield crypto.subtle.digest('SHA-256', buf(accessToken))) : undefined }), privateKey);
    });
}
function publicJwk(key) {
    return __awaiter(this, void 0, void 0, function* () {
        const { kty, e, n, x, y, crv } = yield crypto.subtle.exportKey('jwk', key);
        return { kty, crv, e, n, x, y };
    });
}
export function generateKeyPair(alg, options) {
    var _a, _b, _c;
    return __awaiter(this, void 0, void 0, function* () {
        let algorithm;
        if (typeof alg !== 'string' || alg.length === 0) {
            throw new TypeError('"alg" must be a non-empty string');
        }
        switch (alg) {
            case 'PS256':
                algorithm = {
                    name: 'RSA-PSS',
                    hash: 'SHA-256',
                    modulusLength: (_a = options === null || options === void 0 ? void 0 : options.modulusLength) !== null && _a !== void 0 ? _a : 2048,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                };
                break;
            case 'RS256':
                algorithm = {
                    name: 'RSASSA-PKCS1-v1_5',
                    hash: 'SHA-256',
                    modulusLength: (_b = options === null || options === void 0 ? void 0 : options.modulusLength) !== null && _b !== void 0 ? _b : 2048,
                    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                };
                break;
            case 'ES256':
                algorithm = { name: 'ECDSA', namedCurve: 'P-256' };
                break;
            case 'EdDSA':
                algorithm = { name: 'Ed25519' };
                break;
            default:
                throw new UnsupportedOperationError();
        }
        return (crypto.subtle.generateKey(algorithm, (_c = options === null || options === void 0 ? void 0 : options.extractable) !== null && _c !== void 0 ? _c : false, ['sign', 'verify']));
    });
}
