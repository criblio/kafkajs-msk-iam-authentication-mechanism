import { Mechanism } from "kafkajs";
import { AwsCredentialIdentity, Provider } from "@aws-sdk/types";
export type Options = {
    /**
     * The AWS region in which the Kafka broker exists.
     */
    region: string;
    /**
     * Provides the time period, in seconds, for which the generated presigned URL is valid.
     * @default 900
     */
    ttl?: string;
    /**
     * Is a string passed in by the client library to describe the client.
     * @default MSK_IAM
     */
    userAgent?: string;
    /**
     * Credential provider.
     */
    credentials: AwsCredentialIdentity | Provider<AwsCredentialIdentity>;
};
export declare const createMechanism: (options: Options, mechanism?: string) => Mechanism;
