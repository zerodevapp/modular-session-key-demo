import { Buffer } from "buffer"
import { KERNEL_ADDRESSES } from "@zerodev/sdk"
import type { KernelValidator } from "@zerodev/sdk/types"
import { ValidatorMode } from "@zerodev/sdk/types"
import type { TypedData } from "abitype"
import { startAuthentication, startRegistration } from "@simplewebauthn/browser"
import { type UserOperation, getUserOperationHash } from "permissionless"
import { SignTransactionNotSupportedBySmartAccount } from "permissionless/accounts"
import {
    encodeAbiParameters,
    maxUint256,
    LocalAccount,
    type Address,
    type Chain,
    type Client,
    type Transport,
    type TypedDataDefinition
} from "viem"
import { toAccount } from "viem/accounts"
import { signMessage, signTypedData } from "viem/actions"
import { getChainId } from "viem/actions"
import { WEBAUTHN_VALIDATOR_ADDRESS } from "./index.js"
import { uint8ArrayToHexString } from "../utils.js"
import {
    b64ToBytes,
    findQuoteIndices,
    parseAndNormalizeSig
} from "../../utils.js"

export async function createPasskeyValidator<
    TTransport extends Transport = Transport,
    TChain extends Chain | undefined = Chain | undefined
>(
    client: Client<TTransport, TChain, undefined>,
    {
        passkeyName,
        registerOptionUrl,
        registerVerifyUrl,
        signInitiateUrl,
        signVerifyUrl,
        entryPoint = KERNEL_ADDRESSES.ENTRYPOINT_V0_6,
        validatorAddress = WEBAUTHN_VALIDATOR_ADDRESS
    }: {
        passkeyName: string
        registerOptionUrl: string
        registerVerifyUrl: string
        signInitiateUrl: string
        signVerifyUrl: string
        entryPoint?: Address
        validatorAddress?: Address
    }
): Promise<KernelValidator<"WebAuthnValidator">> {
    // Get registration options
    const registerOptionsResponse = await fetch(registerOptionUrl, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ username: passkeyName }),
        credentials: "include"
    })
    const registerOptions = await registerOptionsResponse.json()
    const registerCred = await startRegistration(registerOptions)

    // Verify registration
    const registerVerifyResponse = await fetch(registerVerifyUrl, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ username: passkeyName, cred: registerCred }),
        credentials: "include"
    })

    const registerVerifyResult = await registerVerifyResponse.json()
    if (!registerVerifyResult.verified) {
        throw new Error("Registration not verified")
    }

    const pubKey = registerCred.response.publicKey
    if (!pubKey) {
        throw new Error("No public key returned from registration credential")
    }

    console.log("register raw pubKey", pubKey)

    // Import the key
    const spkiDer = Buffer.from(pubKey, "base64")
    const key = await crypto.subtle.importKey(
        "spki",
        spkiDer,
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        true,
        ["verify"]
    )

    // Export the key to the raw format
    const rawKey = await crypto.subtle.exportKey("raw", key)
    const rawKeyBuffer = Buffer.from(rawKey)

    // The first byte is 0x04 (uncompressed), followed by x and y coordinates (32 bytes each for P-256)
    const pubKeyX = rawKeyBuffer.subarray(1, 33).toString("hex")
    const pubKeyY = rawKeyBuffer.subarray(33).toString("hex")

    console.log("pubKeyX", pubKeyX)
    console.log("pubKeyY", pubKeyY)

    // build account with passkey
    const account: LocalAccount = toAccount({
        // note that this address will be overwritten by actual address
        address: "0x0000000000000000000000000000000000000000",
        async signMessage({ message }) {
            // convert SignMessage to string
            let messageContent: string
            if (typeof message === "string") {
                // message is a string
                messageContent = message
            } else if ("raw" in message && typeof message.raw === "string") {
                // message.raw is a Hex string
                messageContent = message.raw
            } else if ("raw" in message && message.raw instanceof Uint8Array) {
                // message.raw is a ByteArray
                messageContent = message.raw.toString()
            } else {
                throw new Error("Unsupported message format")
            }

            // remove 0x prefix if present
            const formattedMessage = messageContent.startsWith("0x")
                ? messageContent.slice(2)
                : messageContent

            // initiate signing
            const signInitiateResponse = await fetch(signInitiateUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ data: formattedMessage }),
                credentials: "include"
            })
            const signInitiateResult = await signInitiateResponse.json()

            // prepare assertion options
            const assertionOptions = {
                challenge: signInitiateResult.challenge,
                allowCredentials: signInitiateResult.allowCredentials
            }

            // start authentication (signing)
            const cred = await startAuthentication(assertionOptions)

            // verify signature from server
            const verifyResponse = await fetch(signVerifyUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ cred }),
                credentials: "include"
            })

            const verifyResult = await verifyResponse.json()

            if (!verifyResult.success) {
                throw new Error("Signature not verified")
            }

            // get authenticator data
            const authenticatorData = verifyResult.authenticatorData
            const authenticatorDataHex = uint8ArrayToHexString(
                b64ToBytes(authenticatorData)
            )

            // get client data JSON
            const clientDataJSON = atob(cred.response.clientDataJSON)

            // get challenge and response type location
            const { beforeType, beforeChallenge } =
                findQuoteIndices(clientDataJSON)

            // get signature r,s
            const signature = verifyResult.signature
            const signatureHex = uint8ArrayToHexString(b64ToBytes(signature))
            const { r, s } = parseAndNormalizeSig(signatureHex)

            // encode signature
            const encodedSignature = encodeAbiParameters(
                [
                    { name: "authenticatorData", type: "bytes" },
                    { name: "clientDataJSON", type: "string" },
                    { name: "challengeLocation", type: "uint256" },
                    { name: "responseTypeLocation", type: "uint256" },
                    { name: "r", type: "uint256" },
                    { name: "s", type: "uint256" }
                ],
                [
                    authenticatorDataHex,
                    clientDataJSON,
                    beforeChallenge,
                    beforeType,
                    BigInt(r),
                    BigInt(s)
                ]
            )
            return encodedSignature
        },
        async signTransaction(_, __) {
            throw new SignTransactionNotSupportedBySmartAccount()
        },
        async signTypedData<
            const TTypedData extends TypedData | Record<string, unknown>,
            TPrimaryType extends
                | keyof TTypedData
                | "EIP712Domain" = keyof TTypedData
        >(typedData: TypedDataDefinition<TTypedData, TPrimaryType>) {
            // TODO: implement
            return signTypedData<TTypedData, TPrimaryType, TChain, undefined>(
                client,
                {
                    account,
                    ...typedData
                }
            )
        }
    })

    // Fetch chain id
    const chainId = await getChainId(client)

    return {
        ...account,
        address: validatorAddress,
        source: "WebAuthnValidator",
        async getEnableData() {
            return encodeAbiParameters(
                [
                    {
                        components: [
                            {
                                name: "x",
                                type: "uint256"
                            },
                            {
                                name: "y",
                                type: "uint256"
                            }
                        ],
                        name: "pubKey",
                        type: "tuple"
                    }
                ],
                [{ x: BigInt(`0x${pubKeyX}`), y: BigInt(`0x${pubKeyY}`) }]
            )
        },
        async getNonceKey() {
            return 0n
        },
        async signUserOperation(userOperation: UserOperation) {
            const hash = getUserOperationHash({
                userOperation: {
                    ...userOperation,
                    signature: "0x"
                },
                entryPoint: entryPoint,
                chainId: chainId
            })

            const signature = await signMessage(client, {
                account,
                message: { raw: hash }
            })
            return signature
        },
        async getDummySignature() {
            const encodedSignature = encodeAbiParameters(
                [
                    { name: "authenticatorData", type: "bytes" },
                    { name: "clientDataJSON", type: "string" },
                    { name: "challengeLocation", type: "uint256" },
                    { name: "responseTypeLocation", type: "uint256" },
                    { name: "r", type: "uint256" },
                    { name: "s", type: "uint256" }
                ],
                [
                    "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    '{"type":"webauthn.get","challenge":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","origin":"https://example.com"}',
                    maxUint256,
                    maxUint256,
                    11111111111111111111111111111111111111111111111111111111111111111111111111111n,
                    22222222222222222222222222222222222222222222222222222222222222222222222222222n
                ]
            )
            return encodedSignature
        },
        async getValidatorMode() {
            return ValidatorMode.sudo
        }
    }
}

export async function getPasskeyValidator<
    TTransport extends Transport = Transport,
    TChain extends Chain | undefined = Chain | undefined
>(
    client: Client<TTransport, TChain, undefined>,
    {
        loginOptionUrl,
        loginVerifyUrl,
        signInitiateUrl,
        signVerifyUrl,
        entryPoint = KERNEL_ADDRESSES.ENTRYPOINT_V0_6,
        validatorAddress = WEBAUTHN_VALIDATOR_ADDRESS
    }: {
        loginOptionUrl: string
        loginVerifyUrl: string
        signInitiateUrl: string
        signVerifyUrl: string
        entryPoint?: Address
        validatorAddress?: Address
    }
): Promise<KernelValidator<"WebAuthnValidator">> {
    //
    const loginOptionsResponse = await fetch(loginOptionUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include"
    })
    const loginOptions = await loginOptionsResponse.json()

    console.log("loginOptions", loginOptions)
    const loginCred = await startAuthentication(loginOptions)

    const loginVerifyResponse = await fetch(loginVerifyUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ cred: loginCred }),
        credentials: "include"
    })

    const loginVerifyResult = await loginVerifyResponse.json()

    console.log("loginVerifyResult", loginVerifyResult)

    if (!loginVerifyResult.verification.verified) {
        throw new Error("Login not verified")
    }

    const pubKey = loginVerifyResult.pubkey // Uint8Array pubkey
    if (!pubKey) {
        throw new Error("No public key returned from login verify credential")
    }

    // Import the key
    const spkiDer = Buffer.from(pubKey, "base64")
    const key = await crypto.subtle.importKey(
        "spki",
        spkiDer,
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        true,
        ["verify"]
    )

    // Export the key to the raw format
    const rawKey = await crypto.subtle.exportKey("raw", key)
    const rawKeyBuffer = Buffer.from(rawKey)

    // The first byte is 0x04 (uncompressed), followed by x and y coordinates (32 bytes each for P-256)
    const pubKeyX = rawKeyBuffer.subarray(1, 33).toString("hex")
    const pubKeyY = rawKeyBuffer.subarray(33).toString("hex")

    console.log("pubKeyX", pubKeyX)
    console.log("pubKeyY", pubKeyY)

    // build account with passkey
    const account: LocalAccount = toAccount({
        // note that this address will be overwritten by actual address
        address: "0x0000000000000000000000000000000000000000",
        async signMessage({ message }) {
            // convert SignMessage to string
            let messageContent: string
            if (typeof message === "string") {
                // message is a string
                messageContent = message
            } else if ("raw" in message && typeof message.raw === "string") {
                // message.raw is a Hex string
                messageContent = message.raw
            } else if ("raw" in message && message.raw instanceof Uint8Array) {
                // message.raw is a ByteArray
                messageContent = message.raw.toString()
            } else {
                throw new Error("Unsupported message format")
            }

            // remove 0x prefix if present
            const formattedMessage = messageContent.startsWith("0x")
                ? messageContent.slice(2)
                : messageContent

            // initiate signing
            const signInitiateResponse = await fetch(signInitiateUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ data: formattedMessage }),
                credentials: "include"
            })
            const signInitiateResult = await signInitiateResponse.json()

            // prepare assertion options
            const assertionOptions = {
                challenge: signInitiateResult.challenge,
                allowCredentials: signInitiateResult.allowCredentials
            }

            // start authentication (signing)
            const cred = await startAuthentication(assertionOptions)

            // verify signature from server
            const verifyResponse = await fetch(signVerifyUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ cred }),
                credentials: "include"
            })

            const verifyResult = await verifyResponse.json()

            if (!verifyResult.success) {
                throw new Error("Signature not verified")
            }

            // get authenticator data
            const authenticatorData = verifyResult.authenticatorData
            const authenticatorDataHex = uint8ArrayToHexString(
                b64ToBytes(authenticatorData)
            )

            // get client data JSON
            const clientDataJSON = atob(cred.response.clientDataJSON)

            // get challenge and response type location
            const { beforeType, beforeChallenge } =
                findQuoteIndices(clientDataJSON)

            // get signature r,s
            const signature = verifyResult.signature
            const signatureHex = uint8ArrayToHexString(b64ToBytes(signature))
            const { r, s } = parseAndNormalizeSig(signatureHex)

            // encode signature
            const encodedSignature = encodeAbiParameters(
                [
                    { name: "authenticatorData", type: "bytes" },
                    { name: "clientDataJSON", type: "string" },
                    { name: "challengeLocation", type: "uint256" },
                    { name: "responseTypeLocation", type: "uint256" },
                    { name: "r", type: "uint256" },
                    { name: "s", type: "uint256" }
                ],
                [
                    authenticatorDataHex,
                    clientDataJSON,
                    beforeChallenge,
                    beforeType,
                    BigInt(r),
                    BigInt(s)
                ]
            )
            return encodedSignature
        },
        async signTransaction(_, __) {
            throw new SignTransactionNotSupportedBySmartAccount()
        },
        async signTypedData<
            const TTypedData extends TypedData | Record<string, unknown>,
            TPrimaryType extends
                | keyof TTypedData
                | "EIP712Domain" = keyof TTypedData
        >(typedData: TypedDataDefinition<TTypedData, TPrimaryType>) {
            // TODO: implement
            return signTypedData<TTypedData, TPrimaryType, TChain, undefined>(
                client,
                {
                    account,
                    ...typedData
                }
            )
        }
    })

    // Fetch chain id
    const chainId = await getChainId(client)

    return {
        ...account,
        address: validatorAddress,
        source: "WebAuthnValidator",
        async getEnableData() {
            return encodeAbiParameters(
                [
                    {
                        components: [
                            {
                                name: "x",
                                type: "uint256"
                            },
                            {
                                name: "y",
                                type: "uint256"
                            }
                        ],
                        name: "pubKey",
                        type: "tuple"
                    }
                ],
                [{ x: BigInt(`0x${pubKeyX}`), y: BigInt(`0x${pubKeyY}`) }]
            )
        },
        async getNonceKey() {
            return 0n
        },
        async signUserOperation(userOperation: UserOperation) {
            const hash = getUserOperationHash({
                userOperation: {
                    ...userOperation,
                    signature: "0x"
                },
                entryPoint: entryPoint,
                chainId: chainId
            })

            const signature = await signMessage(client, {
                account,
                message: { raw: hash }
            })
            return signature
        },
        async getDummySignature() {
            const encodedSignature = encodeAbiParameters(
                [
                    { name: "authenticatorData", type: "bytes" },
                    { name: "clientDataJSON", type: "string" },
                    { name: "challengeLocation", type: "uint256" },
                    { name: "responseTypeLocation", type: "uint256" },
                    { name: "r", type: "uint256" },
                    { name: "s", type: "uint256" }
                ],
                [
                    "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
                    '{"type":"webauthn.get","challenge":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","origin":"https://example.com"}',
                    maxUint256,
                    maxUint256,
                    11111111111111111111111111111111111111111111111111111111111111111111111111111n,
                    22222222222222222222222222222222222222222222222222222222222222222222222222222n
                ]
            )
            return encodedSignature
        },
        async getValidatorMode() {
            return ValidatorMode.sudo
        }
    }
}
