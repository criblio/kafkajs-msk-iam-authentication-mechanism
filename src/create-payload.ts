import { AwsCredentialIdentity, Provider } from "@aws-sdk/types";
import { SourceData } from "@aws-sdk/types";
import { createHash } from "crypto";
import { Sha256 } from "@aws-crypto/sha256-js";
import { toHex } from '@aws-sdk/util-hex-encoding';
import { toUint8Array } from '@aws-sdk/util-utf8';
import {
  ACTION,
  ALGORITHM,
  HASHED_PAYLOAD,
  SERVICE,
  SIGNED_HEADERS,
  Options,
} from ".";

// awhittier: Constants copied from aws-sdk-js-v3:
const MAX_CACHE_SIZE = 50
const KEY_TYPE_IDENTIFIER = 'aws4_request'

/** @internal */
export type DateLike = number | Date | string;

/** @internal */
export type Payload = {
  version: string;
  "user-agent": string;
  host: string;
  action: string;
  "x-amz-credential": string;
  "x-amz-algorithm": string;
  "x-amz-date": string;
  "x-amz-security-token"?: string;
  "x-amz-signedheaders": string;
  "x-amz-expires": string;
  "x-amz-signature": string;
};

/** @internal */
export class CreatePayload {
  private readonly region: string;
  private readonly ttl: string;
  private readonly userAgent: string;
  private readonly credentials:
    | AwsCredentialIdentity
    | Provider<AwsCredentialIdentity>;
  private readonly cacheQueue: string[];
  private readonly signingKeyCache: Map<string, Uint8Array>;

  constructor(options: Options) {
    const { region, ttl, userAgent, credentials } = options;
    this.region = region;
    this.ttl = ttl ?? "900";
    this.userAgent = userAgent ?? "MSK_IAM";
    this.credentials = credentials;
    this.cacheQueue = []
    this.signingKeyCache = new Map<string, Uint8Array>();
  }

  timestampYYYYmmDDFormat(date: DateLike): string {
    const d = new Date(date);
    return this.timestampYYYYmmDDTHHMMSSZFormat(d).substring(0, 8);
  }

  timestampYYYYmmDDTHHMMSSZFormat(date: DateLike): string {
    const d = new Date(date);
    return d.toISOString().replace(/[-.:]/g, "").substring(0, 15).concat("Z");
  }

  generateCanonicalHeaders(brokerHost: string): string {
    return `host:${brokerHost}\n`;
  }

  generateXAmzCredential(accessKeyId: string, date: string): string {
    return `${accessKeyId}/${date}/${this.region}/${SERVICE}/aws4_request`;
  }

  generateStringToSign(date: DateLike, canonicalRequest: string): string {
    return `${ALGORITHM}
${this.timestampYYYYmmDDTHHMMSSZFormat(date)}
${this.timestampYYYYmmDDFormat(date)}/${this.region}/${SERVICE}/aws4_request
${createHash("sha256").update(canonicalRequest, "utf8").digest("hex")}`;
  }

  generateCanonicalQueryString(
    date: string,
    xAmzCredential: string,
    sessionToken?: string
  ): string {
    let canonicalQueryString = "";
    canonicalQueryString += `${encodeURIComponent(
      "Action"
    )}=${encodeURIComponent(ACTION)}&`;
    canonicalQueryString += `${encodeURIComponent(
      "X-Amz-Algorithm"
    )}=${encodeURIComponent(ALGORITHM)}&`;
    canonicalQueryString += `${encodeURIComponent(
      "X-Amz-Credential"
    )}=${encodeURIComponent(xAmzCredential)}&`;
    canonicalQueryString += `${encodeURIComponent(
      "X-Amz-Date"
    )}=${encodeURIComponent(date)}&`;
    canonicalQueryString += `${encodeURIComponent(
      "X-Amz-Expires"
    )}=${encodeURIComponent(this.ttl)}&`;

    if (sessionToken !== undefined) {
      canonicalQueryString += `${encodeURIComponent(
        "X-Amz-Security-Token"
      )}=${encodeURIComponent(sessionToken)}&`;
    }

    canonicalQueryString += `${encodeURIComponent(
      "X-Amz-SignedHeaders"
    )}=${encodeURIComponent(SIGNED_HEADERS)}`;

    return canonicalQueryString;
  }

  generateCanonicalRequest(
    canonicalQueryString: string,
    canonicalHeaders: string,
    signedHeaders: string,
    hashedPayload: string
  ): string {
    return (
      "GET\n" +
      "/\n" +
      canonicalQueryString +
      "\n" +
      canonicalHeaders +
      "\n" +
      signedHeaders +
      "\n" +
      hashedPayload
    );
  }

  /* awhittier: logic to replace signature-v4 */

  iso8601 (time: Date) {
    return time.toISOString().replace(/\.\d{3}Z$/, 'Z')
  }

  toDate (time: number | string) {
    if (typeof time === 'number') {
      return new Date(time * 1000)
    }

    if (typeof time === 'string') {
      if (Number(time)) {
        return new Date(Number(time) * 1000)
      }
      return new Date(time)
    }

    return time
  }

  formatDate (now: Date) {
    const longDate = this.iso8601(now).replace(/[-:]/g, '')
    return {
      longDate,
      shortDate: longDate.slice(0, 8)
    }
  }

  hmac (secret: SourceData, data: string): Promise<Uint8Array> {
    const hash = new Sha256(secret)
    hash.update(data)
    return hash.digest()
  };

  async getSigningKey (credentials: AwsCredentialIdentity, shortDate:string, region: string): Promise<Uint8Array> {
    const credsHash = await this.hmac(credentials.secretAccessKey, credentials.accessKeyId)
    const cacheKey = `${shortDate}:${region}:${SERVICE}:${toHex(credsHash)}:${credentials.sessionToken}`
    if (this.signingKeyCache.has(cacheKey)) {
      return this.signingKeyCache.get(cacheKey)!;
    }
    this.cacheQueue.push(cacheKey)
    while (this.cacheQueue.length > MAX_CACHE_SIZE) {
      const key = this.cacheQueue.shift()!;
      this.signingKeyCache.delete(key);
    }

    let key = toUint8Array(`AWS4${credentials.secretAccessKey}`);
    for (const signable of [shortDate, region, SERVICE, KEY_TYPE_IDENTIFIER]) {
      key = await this.hmac(key, signable)
    }
    this.signingKeyCache.set(cacheKey, key);
    return key;
  }

  async sign (toSign: string, region: string, credentials: AwsCredentialIdentity) {
    const { shortDate } = this.formatDate(new Date())

    const signingKey = await this.getSigningKey(credentials, shortDate, region)
    const hash = new Sha256(signingKey)
    hash.update(toUint8Array(toSign))
    return toHex(await hash.digest())
  }

  /* awhittier: end logic to replace signature-v4 */

  async create({ brokerHost }: { brokerHost: string }): Promise<Payload> {
    if (!brokerHost) {
      throw new Error("Missing values");
    }
    const credentials = typeof this.credentials === "function"
      ? await this.credentials()
      : this.credentials;
    const { accessKeyId, sessionToken } = credentials;
    const now = Date.now();
    const xAmzCredential = this.generateXAmzCredential(
      accessKeyId,
      this.timestampYYYYmmDDFormat(now)
    );
    const canonicalHeaders = this.generateCanonicalHeaders(brokerHost);
    const canonicalQueryString = this.generateCanonicalQueryString(
      this.timestampYYYYmmDDTHHMMSSZFormat(now),
      xAmzCredential,
      sessionToken
    );
    const canonicalRequest = this.generateCanonicalRequest(
      canonicalQueryString,
      canonicalHeaders,
      SIGNED_HEADERS,
      HASHED_PAYLOAD
    ); //
    const stringToSign = this.generateStringToSign(now, canonicalRequest);

    // awhittier: replaces the call out to aws-sdk/signature-v4
    const signature = await this.sign(stringToSign, this.region, credentials);

    return {
      version: "2020_10_22",
      "user-agent": this.userAgent,
      host: brokerHost,
      action: ACTION,
      "x-amz-credential": xAmzCredential,
      "x-amz-algorithm": ALGORITHM,
      "x-amz-date": this.timestampYYYYmmDDTHHMMSSZFormat(now),
      "x-amz-security-token": sessionToken,
      "x-amz-signedheaders": SIGNED_HEADERS,
      "x-amz-expires": this.ttl,
      "x-amz-signature": signature,
    };
  }
}
