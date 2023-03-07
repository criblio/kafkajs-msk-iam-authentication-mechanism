"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CreatePayload = void 0;
const crypto_1 = require("crypto");
const sha256_js_1 = require("@aws-crypto/sha256-js");
const util_hex_encoding_1 = require("@aws-sdk/util-hex-encoding");
const util_utf8_1 = require("@aws-sdk/util-utf8");
const _1 = require(".");
// awhittier: Constants copied from aws-sdk-js-v3:
const MAX_CACHE_SIZE = 50;
const KEY_TYPE_IDENTIFIER = 'aws4_request';
/** @internal */
class CreatePayload {
    constructor(options) {
        const { region, ttl, userAgent, credentials } = options;
        this.region = region;
        this.ttl = ttl !== null && ttl !== void 0 ? ttl : "900";
        this.userAgent = userAgent !== null && userAgent !== void 0 ? userAgent : "MSK_IAM";
        this.credentials = credentials;
        this.cacheQueue = [];
        this.signingKeyCache = new Map();
    }
    timestampYYYYmmDDFormat(date) {
        const d = new Date(date);
        return this.timestampYYYYmmDDTHHMMSSZFormat(d).substring(0, 8);
    }
    timestampYYYYmmDDTHHMMSSZFormat(date) {
        const d = new Date(date);
        return d.toISOString().replace(/[-.:]/g, "").substring(0, 15).concat("Z");
    }
    generateCanonicalHeaders(brokerHost) {
        return `host:${brokerHost}\n`;
    }
    generateXAmzCredential(accessKeyId, date) {
        return `${accessKeyId}/${date}/${this.region}/${_1.SERVICE}/aws4_request`;
    }
    generateStringToSign(date, canonicalRequest) {
        return `${_1.ALGORITHM}
${this.timestampYYYYmmDDTHHMMSSZFormat(date)}
${this.timestampYYYYmmDDFormat(date)}/${this.region}/${_1.SERVICE}/aws4_request
${(0, crypto_1.createHash)("sha256").update(canonicalRequest, "utf8").digest("hex")}`;
    }
    generateCanonicalQueryString(date, xAmzCredential, sessionToken) {
        let canonicalQueryString = "";
        canonicalQueryString += `${encodeURIComponent("Action")}=${encodeURIComponent(_1.ACTION)}&`;
        canonicalQueryString += `${encodeURIComponent("X-Amz-Algorithm")}=${encodeURIComponent(_1.ALGORITHM)}&`;
        canonicalQueryString += `${encodeURIComponent("X-Amz-Credential")}=${encodeURIComponent(xAmzCredential)}&`;
        canonicalQueryString += `${encodeURIComponent("X-Amz-Date")}=${encodeURIComponent(date)}&`;
        canonicalQueryString += `${encodeURIComponent("X-Amz-Expires")}=${encodeURIComponent(this.ttl)}&`;
        if (sessionToken !== undefined) {
            canonicalQueryString += `${encodeURIComponent("X-Amz-Security-Token")}=${encodeURIComponent(sessionToken)}&`;
        }
        canonicalQueryString += `${encodeURIComponent("X-Amz-SignedHeaders")}=${encodeURIComponent(_1.SIGNED_HEADERS)}`;
        return canonicalQueryString;
    }
    generateCanonicalRequest(canonicalQueryString, canonicalHeaders, signedHeaders, hashedPayload) {
        return ("GET\n" +
            "/\n" +
            canonicalQueryString +
            "\n" +
            canonicalHeaders +
            "\n" +
            signedHeaders +
            "\n" +
            hashedPayload);
    }
    /* awhittier: logic to replace signature-v4 */
    iso8601(time) {
        return time.toISOString().replace(/\.\d{3}Z$/, 'Z');
    }
    toDate(time) {
        if (typeof time === 'number') {
            return new Date(time * 1000);
        }
        if (typeof time === 'string') {
            if (Number(time)) {
                return new Date(Number(time) * 1000);
            }
            return new Date(time);
        }
        return time;
    }
    formatDate(now) {
        const longDate = this.iso8601(now).replace(/[-:]/g, '');
        return {
            longDate,
            shortDate: longDate.slice(0, 8)
        };
    }
    hmac(secret, data) {
        const hash = new sha256_js_1.Sha256(secret);
        hash.update(data);
        return hash.digest();
    }
    ;
    getSigningKey(credentials, shortDate, region) {
        return __awaiter(this, void 0, void 0, function* () {
            const credsHash = yield this.hmac(credentials.secretAccessKey, credentials.accessKeyId);
            const cacheKey = `${shortDate}:${region}:${_1.SERVICE}:${(0, util_hex_encoding_1.toHex)(credsHash)}:${credentials.sessionToken}`;
            if (this.signingKeyCache.has(cacheKey)) {
                return this.signingKeyCache.get(cacheKey);
            }
            this.cacheQueue.push(cacheKey);
            while (this.cacheQueue.length > MAX_CACHE_SIZE) {
                const key = this.cacheQueue.shift();
                this.signingKeyCache.delete(key);
            }
            let key = (0, util_utf8_1.toUint8Array)(`AWS4${credentials.secretAccessKey}`);
            for (const signable of [shortDate, region, _1.SERVICE, KEY_TYPE_IDENTIFIER]) {
                key = yield this.hmac(key, signable);
            }
            this.signingKeyCache.set(cacheKey, key);
            return key;
        });
    }
    sign(toSign, region, credentials) {
        return __awaiter(this, void 0, void 0, function* () {
            const { shortDate } = this.formatDate(new Date());
            const signingKey = yield this.getSigningKey(credentials, shortDate, region);
            const hash = new sha256_js_1.Sha256(signingKey);
            hash.update((0, util_utf8_1.toUint8Array)(toSign));
            return (0, util_hex_encoding_1.toHex)(yield hash.digest());
        });
    }
    /* awhittier: end logic to replace signature-v4 */
    create({ brokerHost }) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!brokerHost) {
                throw new Error("Missing values");
            }
            const credentials = typeof this.credentials === "function"
                ? yield this.credentials()
                : this.credentials;
            const { accessKeyId, sessionToken } = credentials;
            const now = Date.now();
            const xAmzCredential = this.generateXAmzCredential(accessKeyId, this.timestampYYYYmmDDFormat(now));
            const canonicalHeaders = this.generateCanonicalHeaders(brokerHost);
            const canonicalQueryString = this.generateCanonicalQueryString(this.timestampYYYYmmDDTHHMMSSZFormat(now), xAmzCredential, sessionToken);
            const canonicalRequest = this.generateCanonicalRequest(canonicalQueryString, canonicalHeaders, _1.SIGNED_HEADERS, _1.HASHED_PAYLOAD); //
            const stringToSign = this.generateStringToSign(now, canonicalRequest);
            // awhittier: replaces the call out to aws-sdk/signature-v4
            const signature = yield this.sign(stringToSign, this.region, credentials);
            return {
                version: "2020_10_22",
                "user-agent": this.userAgent,
                host: brokerHost,
                action: _1.ACTION,
                "x-amz-credential": xAmzCredential,
                "x-amz-algorithm": _1.ALGORITHM,
                "x-amz-date": this.timestampYYYYmmDDTHHMMSSZFormat(now),
                "x-amz-security-token": sessionToken,
                "x-amz-signedheaders": _1.SIGNED_HEADERS,
                "x-amz-expires": this.ttl,
                "x-amz-signature": signature,
            };
        });
    }
}
exports.CreatePayload = CreatePayload;
