import { AwsCredentialIdentity } from "@aws-sdk/types";
import { SourceData } from "@aws-sdk/types";
import { Options } from ".";
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
export declare class CreatePayload {
    private readonly region;
    private readonly ttl;
    private readonly userAgent;
    private readonly credentials;
    private readonly cacheQueue;
    private readonly signingKeyCache;
    constructor(options: Options);
    timestampYYYYmmDDFormat(date: DateLike): string;
    timestampYYYYmmDDTHHMMSSZFormat(date: DateLike): string;
    generateCanonicalHeaders(brokerHost: string): string;
    generateXAmzCredential(accessKeyId: string, date: string): string;
    generateStringToSign(date: DateLike, canonicalRequest: string): string;
    generateCanonicalQueryString(date: string, xAmzCredential: string, sessionToken?: string): string;
    generateCanonicalRequest(canonicalQueryString: string, canonicalHeaders: string, signedHeaders: string, hashedPayload: string): string;
    iso8601(time: Date): string;
    toDate(time: number | string): Date;
    formatDate(now: Date): {
        longDate: string;
        shortDate: string;
    };
    hmac(secret: SourceData, data: string): Promise<Uint8Array>;
    getSigningKey(credentials: AwsCredentialIdentity, shortDate: string, region: string): Promise<Uint8Array>;
    sign(toSign: string, region: string, credentials: AwsCredentialIdentity): Promise<string>;
    create({ brokerHost }: {
        brokerHost: string;
    }): Promise<Payload>;
}
