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
    convertBase64PublicKeyToXY,
    parseAndNormalizeSig
} from "../../utils.js"

export async function createPasskeyValidator<
    TTransport extends Transport = Transport,
    TChain extends Chain | undefined = Chain | undefined,
    TSource extends string = "custom",
    TAddress extends Address = Address
>(
    client: Client<TTransport, TChain, undefined>,
    {
        passkeyName,
        createApiUrl,
        credentialApiUrl,
        entryPoint = KERNEL_ADDRESSES.ENTRYPOINT_V0_6,
        validatorAddress = WEBAUTHN_VALIDATOR_ADDRESS
    }: {
        passkeyName?: string
        createApiUrl?: string
        credentialApiUrl?: string
        entryPoint?: Address
        validatorAddress?: Address
    }
): Promise<KernelValidator<"WebAuthnValidator">> {
    //
    const registerOptionsResponse = await fetch(
        "http://localhost:8080/register/options",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: passkeyName }),
            credentials: "include"
        }
    )
    const registerOptions = await registerOptionsResponse.json()

    const registerCred = await startRegistration(registerOptions)

    console.log("register cred: ", registerCred)

    const registerVerifyResponse = await fetch(
        "http://localhost:8080/register/verify",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: passkeyName, cred: registerCred }),
            credentials: "include"
        }
    )

    const pubKey = registerCred.response.publicKey
    if (!pubKey) {
        throw new Error("No public key returned")
    }

    const spkiDer = Buffer.from(pubKey, "base64")

    // Import the key
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

    // Convert ArrayBuffer to Buffer
    const rawKeyBuffer = Buffer.from(rawKey)

    // The first byte is 0x04 (uncompressed), followed by x and y coordinates (32 bytes each for P-256)
    const pubKeyX = rawKeyBuffer.subarray(1, 33).toString("hex")
    const pubKeyY = rawKeyBuffer.subarray(33).toString("hex")

    console.log("x: ", pubKeyX)
    console.log("y: ", pubKeyY)

    const loginOptionsResponse = await fetch(
        "http://localhost:8080/login/options",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: passkeyName }),
            credentials: "include"
        }
    )
    const loginOptions = await loginOptionsResponse.json()

    const loginCred = await startAuthentication(loginOptions)

    const LoginVerifyResponse = await fetch(
        "http://localhost:8080/login/verify",
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ cred: loginCred }),
            credentials: "include"
        }
    )

    // build account with passkey
    const account = toAccount({
        address: "0x0000000000000000000000000000000000000000", // TODO: temp zero address
        // note that signMessage should be called in response to a user action
        async signMessage({ message }) {
            console.log("message: ", message)

            let messageContent
            if (typeof message === "string") {
                // message is a string
                messageContent = message
            } else if ("raw" in message && typeof message.raw === "string") {
                // message.raw is a Hex string
                messageContent = message.raw
            } else if ("raw" in message && message.raw instanceof Uint8Array) {
                // message.raw is a ByteArray
                messageContent = message.raw
            } else {
                throw new Error("Unsupported message format")
            }

            console.log("messageContent: ", messageContent)

            const converted = (messageContent as string).startsWith("0x")
                ? messageContent.slice(2)
                : messageContent

            const signInitiateResponse = await fetch(
                "http://localhost:8080/sign-initiate",
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ data: converted }),
                    credentials: "include"
                }
            )

            const signInitiateResult = await signInitiateResponse.json()

            const challengeBase64 = signInitiateResult.challenge
            const challengeArrayBuffer = b64ToBytes(challengeBase64)
            const challengeUint8Array = new Uint8Array(challengeArrayBuffer)
            const challengeHex = uint8ArrayToHexString(challengeUint8Array)

            console.log(
                "signInitiateResult.challenge: ",
                signInitiateResult.challenge
            )

            const assertionOptions = {
                challenge: signInitiateResult.challenge,
                allowCredentials: signInitiateResult.allowCredentials
            }

            const cred = await startAuthentication(assertionOptions)

            const verifyResponse = await fetch(
                "http://localhost:8080/sign-verify",
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ cred }),
                    credentials: "include"
                }
            )

            const verifyResult = await verifyResponse.json()
            console.log("verifyResult: ", verifyResult)

            const signature = verifyResult.signature
            const authenticatorData = verifyResult.authenticatorData

            const authenticatorDataHex = uint8ArrayToHexString(
                b64ToBytes(authenticatorData)
            )
            const signatureHex = uint8ArrayToHexString(b64ToBytes(signature))

            const { r, s } = parseAndNormalizeSig(signatureHex)

            const clientDataJSON = atob(cred.response.clientDataJSON)

            const publicKeyBase64 = verifyResult.publicKeyBase64
            const { x, y } = convertBase64PublicKeyToXY(publicKeyBase64)

            console.log("challenge: ", challengeHex)
            console.log("authenticatorDataHex: ", authenticatorDataHex)
            console.log("clientDataJSON: ", clientDataJSON)
            console.log("r: ", r)
            console.log("s: ", s)
            console.log("x: ", x)
            console.log("y: ", y)

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
                    BigInt(23),
                    BigInt(1),
                    r,
                    s
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

            console.log("userOpHash: ", hash)

            const signature = await signMessage(client, {
                account,
                message: { raw: hash }
            })
            return signature
        },
        async getDummySignature() {
            // 32 bytes
            const authenticatorData =
                "0x02438d3405cadd648e08dbff51bdbeb415913e642189100dc4a012064c870883050002343c"
            const clientDataJSON =
                '{"type":"webauthn.get","challenge":"-q0bkO7eXzE152_SkeSPVLhrYw6PDEtahd5mTKnsnnc","origin":"https://funny-froyo-3f9b75.netlify.app"}'
            const challengeLocation = 1
            const responseTypeLocation = 23
            const r = "0x" + "a".repeat(64)
            const s = "0x" + "a".repeat(64)

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
                    authenticatorData,
                    clientDataJSON,
                    BigInt(challengeLocation),
                    BigInt(responseTypeLocation),
                    BigInt(r),
                    BigInt(s)
                ]
            )

            console.log("dummySignature: ", encodedSignature)
            return encodedSignature
        },
        async getValidatorMode() {
            return ValidatorMode.sudo
        }
    }
}
