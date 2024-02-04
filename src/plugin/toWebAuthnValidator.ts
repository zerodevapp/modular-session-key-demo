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
    const optionsResponse = await fetch(
        "http://localhost:8080/register/options", // TODO: replace with actual url
        {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: "adnpark" }), // Replace with actual username input if needed,
            credentials: "include"
        }
    )
    const options = await optionsResponse.json()

    // const cred = await startRegistration(options)
    const cred = await startRegistration(options)

    console.log("cred: ", cred)

    const pubKey = cred.response.publicKey
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
    const x = rawKeyBuffer.subarray(1, 33).toString("hex")
    const y = rawKeyBuffer.subarray(33).toString("hex")

    console.log("x: ", x)
    console.log("y: ", y)

    // build account with passkey
    const account = toAccount({
        address: "0x0000000000000000000000000000000000000000", // TODO: temp zero address
        // note that signMessage should be called in response to a user action
        async signMessage({ message }) {
            const optionsResponse = await fetch(
                "http://localhost:8080/login/options",
                {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ username: name }),
                    credentials: "include"
                }
            )
            const options = await optionsResponse.json()

            console.log("options response", options)

            const cred1 = await startAuthentication(options)

            console.log("challenge: ", message)

            let challengeString

            // Check if message is a string
            if (typeof message === "string") {
                challengeString = message
            } else if (typeof message === "object" && message.raw) {
                // Assuming message.raw can be a string or Uint8Array
                if (typeof message.raw === "string") {
                    challengeString = message.raw
                } else if (message.raw instanceof Uint8Array) {
                    // Convert Uint8Array to a hex string
                    challengeString = `0x${Buffer.from(message.raw).toString(
                        "hex"
                    )}`
                } else {
                    throw new Error("Unsupported message.raw format")
                }
            } else {
                throw new Error("Unsupported message format")
            }

            console.log("challengeString: ", challengeString)

            const hexString = challengeString.startsWith("0x")
                ? challengeString.substring(2)
                : challengeString

            // convert hash to base64
            const challengeStringBase64 = Buffer.from(
                hexString,
                "hex"
            ).toString("base64")

            console.log("challengeStringBase64: ", challengeStringBase64)

            const cred = await startAuthentication({
                challenge: challengeStringBase64,
                userVerification: "required"
            })

            // get authenticatorData and clientDataJSON
            const authenticatorData = Buffer.from(
                cred.response.authenticatorData,
                "base64"
            ).toString("hex")

            // Assuming cred.response.clientDataJSON is your base64 URL-encoded string
            const clientDataJSONBase64 = cred.response.clientDataJSON

            // Convert base64 URL-encoded string to a standard base64 string
            const base64 = clientDataJSONBase64
                .replace(/-/g, "+")
                .replace(/_/g, "/")

            // Decode from base64 to get the JSON string
            const clientDataJsonString = Buffer.from(base64, "base64").toString(
                "utf-8"
            )

            // Find the locations of the challenge and response type in the clientDataJSON string
            const challengeLocation =
                clientDataJsonString.indexOf('"challenge"')
            const responseTypeLocation = clientDataJsonString.indexOf(
                '"type":"webauthn.get"'
            )

            // get signature r,s
            const signatureBuffer = Buffer.from(
                cred.response.signature,
                "base64"
            )

            // Assuming the signature is in DER format, and using a simple parser
            let offset = 2 // Skip 0x30 (sequence) and the sequence length

            // Parse r
            const rLength = signatureBuffer[offset + 1]
            const r = signatureBuffer
                .subarray(offset + 2, offset + 2 + rLength)
                .toString("hex")
            offset += 2 + rLength

            // Parse s
            const sLength = signatureBuffer[offset + 1]
            const s = signatureBuffer
                .subarray(offset + 2, offset + 2 + sLength)
                .toString("hex")

            console.log("authenticatorData: ", authenticatorData)
            console.log("clientDataJSON: ", clientDataJsonString)
            console.log("challengeLocation: ", challengeLocation)
            console.log("responseTypeLocation: ", responseTypeLocation)
            console.log("r: ", r)
            console.log("s: ", s)

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
                    // `0x${authenticatorData}`,
                    "0x02438d3405cadd648e08dbff51bdbeb415913e642189100dc4a012064c870883050002343c",
                    clientDataJsonString,
                    BigInt(challengeLocation),
                    BigInt(responseTypeLocation),
                    BigInt(`0x${r}`),
                    BigInt(`0x${s}`)
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
                [{ x: BigInt(`0x${x}`), y: BigInt(`0x${y}`) }]
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
            const responseTypeLocation = 27
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
