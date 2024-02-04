import {
    generateAuthenticationOptions,
    generateRegistrationOptions,
    verifyAuthenticationResponse,
    verifyRegistrationResponse
} from "@simplewebauthn/server"
import type {
    AuthenticationResponseJSON,
    RegistrationResponseJSON
} from "@simplewebauthn/typescript-types"
import { jwtVerify, SignJWT } from "jose"
import { Hono } from "hono"
import { getSignedCookie, setSignedCookie } from "hono/cookie"
import { serveStatic } from "hono/bun"
import { logger } from "hono/logger"
import { cors } from "hono/cors"
import {
    parseMakeCredAuthData,
    parseCreateResponse,
    parseSignResponse,
    derKeytoContractFriendlyKey,
    parseAndNormalizeSig,
    uint8ArrayToHexString,
    findQuoteIndices,
    convertBase64PublicKeyToXY,
    splitECDSASignature,
    b64ToBytes
} from "./utils"
import { AuthenticatorDevice } from "@simplewebauthn/typescript-types"
import { base64URLStringToBuffer } from "@simplewebauthn/browser"
import { encodeAbiParameters } from "viem"

// CONSTANTS

const SECRET = new TextEncoder().encode(process.env.JWT_SECRET ?? "development")
const RP_ID = process.env.WEBAUTHN_RP_ID ?? "localhost"
const RP_NAME = process.env.WEBAUTHN_RP_NAME ?? "Bun Passkeys Demo"
const CHALLENGE_TTL = Number(process.env.WEBAUTHN_CHALLENGE_TTL) || 60_000

// UTILS
// Define a simple in-memory KV store interface
interface KVStore {
    get<T>(key: (string | number)[]): Promise<{ value: T | undefined }>
    set(
        key: (string | number)[],
        value: any,
        options?: { expireIn: number }
    ): Promise<void>
    delete(key: (string | number)[]): Promise<void>
}

// Implement the KV store interface
class InMemoryKVStore implements KVStore {
    private store = new Map<string, any>()

    async get<T>(key: (string | number)[]): Promise<{ value: T | undefined }> {
        const value = this.store.get(JSON.stringify(key))
        return { value }
    }

    async set(
        key: (string | number)[],
        value: any,
        options?: { expireIn: number }
    ): Promise<void> {
        // This example does not handle expiration. Implement if needed.
        this.store.set(JSON.stringify(key), value)
    }

    async delete(key: (string | number)[]): Promise<void> {
        this.store.delete(JSON.stringify(key))
    }
}

// Initialize the KV store
const kv: KVStore = new InMemoryKVStore()

function generateJWT(userId: string) {
    return new SignJWT({ userId })
        .setProtectedHeader({ alg: "HS256" })
        .sign(SECRET)
}

function verifyJWT(token: string) {
    return jwtVerify(token, SECRET)
}

function generateRandomID() {
    const id = crypto.getRandomValues(new Uint8Array(32))

    return btoa(
        Array.from(id)
            .map((c) => String.fromCharCode(c))
            .join("")
    )
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "")
}

const authenticatorDevice = {
    credentialID: new Uint8Array(),
    credentialPublicKey: new Uint8Array(),
    counter: 0
}

async function recoverPublicKeyFromSignature(
    cred: AuthenticationResponseJSON
): Promise<string | null> {
    try {
        const verification = await verifyAuthenticationResponse({
            response: cred,
            expectedChallenge: cred.response.clientDataJSON,
            expectedOrigin: "the expected origin",
            expectedRPID: RP_ID,
            authenticator: authenticatorDevice
        })

        if (verification.verified && verification.authenticationInfo) {
            const { signature, authenticatorData } = cred.response
            const { credentialPublicKey } = authenticatorDevice

            const publicKey = await crypto.subtle.importKey(
                "raw",
                credentialPublicKey,
                {
                    name: "ECDSA",
                    namedCurve: "P-256"
                },
                true,
                ["verify"]
            )

            const signatureArray = base64urlToUint8Array(signature)
            const authenticatorDataArray =
                base64urlToUint8Array(authenticatorData)

            const result = await crypto.subtle.verify(
                {
                    name: "ECDSA",
                    hash: "SHA-256"
                },
                publicKey,
                signatureArray,
                authenticatorDataArray
            )

            if (result) {
                return btoa(
                    String.fromCharCode(
                        ...Array.from(
                            new Uint8Array(credentialPublicKey.buffer, 27, 65)
                        )
                    )
                )
            }
        }
    } catch (error) {
        console.error(error)
    }
    return null
}

function base64urlToUint8Array(base64url: string): Uint8Array {
    const padding = "=".repeat((4 - (base64url.length % 4)) % 4)
    const base64 = (base64url + padding).replace(/\-/g, "+").replace(/_/g, "/")

    const rawData = atob(base64)
    const outputArray = new Uint8Array(rawData.length)

    for (let i = 0; i < rawData.length; ++i) {
        outputArray[i] = rawData.charCodeAt(i)
    }

    return outputArray
}

type User = {
    username: string
    data: string
    credentials: Record<string, Credential>
}

type Credential = {
    credentialID: Uint8Array
    credentialPublicKey: Uint8Array
    counter: number
}

type Challenge = true

// RP SERVER

const app = new Hono()

app.use("*", logger())

app.use("*", cors({ credentials: true, origin: (origin) => origin || "*" }))

app.get("/index.js", serveStatic({ path: "./index.js" }))

app.get("/", serveStatic({ path: "./index.html" }))

app.get("/dummy-signature/:userId", async (c) => {
    const userId = c.req.param("userId")

    // Ensure the userId is provided
    if (!userId) {
        return c.text("User ID is required", 400)
    }

    // Retrieve the dummy signature from the KV store
    const dummySignatureData = await kv.get<string>(["dummySignature", userId])

    // Check if the dummy signature exists
    if (!dummySignatureData.value) {
        return c.text("Dummy signature not found", 404)
    }

    // Return the dummy signature to the client
    return c.json({ dummySignature: dummySignatureData.value })
})

// Add new endpoint to process and display data
app.post("/process-authentication", async (c) => {
    const { cred } = await c.req.json()
    const parsedData = parseSignResponse(cred)
    const { r, s } = parseAndNormalizeSig(parsedData.derSig)
    const [x, y] = derKeytoContractFriendlyKey(parseCreateResponse(cred))

    return c.json({ r: r.toString(), s: s.toString(), x, y })
})

app.post("/register/options", async (c) => {
    const { username } = await c.req.json<{ username: string }>()
    console.log({ username })

    const userID = generateRandomID()

    const options = await generateRegistrationOptions({
        rpName: RP_NAME,
        rpID: RP_ID,
        userID,
        userName: username,
        userDisplayName: username,
        authenticatorSelection: {
            residentKey: "required",
            userVerification: "required",
            authenticatorAttachment: "platform"
        }
    })

    console.log({ options })

    await kv.set(["challenges", options.challenge], true, {
        expireIn: CHALLENGE_TTL
    })

    await setSignedCookie(c, "userId", userID, SECRET, {
        httpOnly: true,
        secure: true,
        sameSite: "Strict",
        path: "/",
        maxAge: CHALLENGE_TTL
    })

    return c.json(options)
})

app.get("/public-key/:credentialId", async (c) => {
    const credentialId = c.req.param("credentialId")
    const user = await kv.get<User>(["credentials", credentialId])
    if (!user.value) return c.text("Credential not found", 404)

    const publicKey = user.value.credentials[credentialId].credentialPublicKey
    const publicKeyBase64 = btoa(
        String.fromCharCode(...new Uint8Array(publicKey.buffer))
    )

    return c.json({ publicKey: publicKeyBase64 })
})

app.post("/register/verify", async (c) => {
    console.log("Request headers:", c.req.raw.headers)
    console.log("Cookies:", c.req.raw.headers.get("cookie"))

    const { username, cred } = await c.req.json<{
        username: string
        cred: RegistrationResponseJSON
    }>()
    console.log({ username, cred })

    const userId = await getSignedCookie(c, SECRET, "userId")
    console.log({ userId })
    if (!userId) return new Response("Unauthorized", { status: 401 })
    console.log({ userId })

    const clientData = JSON.parse(atob(cred.response.clientDataJSON))
    console.log({ clientData })

    const challenge = await kv.get<Challenge>([
        "challenges",
        clientData.challenge
    ])
    console.log({ challenge })

    if (!challenge.value) {
        return c.text("Invalid challenge", 400)
    }

    const verification = await verifyRegistrationResponse({
        response: cred,
        expectedChallenge: clientData.challenge,
        expectedRPID: RP_ID,
        expectedOrigin: c.req.header("origin")!, //! Allow from any origin
        requireUserVerification: true
    })
    console.log({ verification })

    if (verification.verified) {
        const { credentialID, credentialPublicKey, counter } =
            verification.registrationInfo!

        await kv.delete(["challenges", clientData.challenge])

        await kv.set(["users", userId], {
            username: username,
            data: "Private user data for " + (username || "Anon"),
            credentials: {
                [cred.id]: {
                    credentialID,
                    credentialPublicKey,
                    counter
                }
            }
        } as User)

        await setSignedCookie(c, "token", await generateJWT(userId), SECRET, {
            httpOnly: true,
            secure: true,
            sameSite: "Strict",
            path: "/",
            maxAge: 600_000
        })

        return c.json(verification)
    }

    return c.text("Unauthorized", 401)
})

app.get("/v1/health", (c) => c.json({ status: "ok" }))

app.post("/login/options", async (c) => {
    const options = await generateAuthenticationOptions({
        userVerification: "required",
        rpID: RP_ID
    })

    console.log({ options })

    await kv.set(["challenges", options.challenge], true, {
        expireIn: CHALLENGE_TTL
    })

    return c.json(options)
})

app.post("/login/verify", async (c) => {
    const { cred } = await c.req.json<{ cred: AuthenticationResponseJSON }>()
    console.log({ cred })

    const clientData = JSON.parse(atob(cred.response.clientDataJSON))

    const clientDataJSON = atob(cred.response.clientDataJSON)
    console.log({ clientData })
    if (typeof clientDataJSON !== "string") {
        throw new Error("clientDataJSON must be a string")
    }

    const userId = cred.response.userHandle
    console.log({ userId })
    if (!userId) return c.json({ error: "Unauthorized" }, { status: 401 })

    const user = await kv.get<User>(["users", userId])
    console.log("Fetched user from KV store:", user)
    if (!user.value) return c.json({ error: "Unauthorized" }, { status: 401 })
    console.log({ user })

    const challenge = await kv.get<Challenge>([
        "challenges",
        clientData.challenge
    ])
    console.log("Fetched challenge from KV store:", challenge)
    if (!challenge.value) {
        return c.text("Invalid challenge", 400)
    }

    console.log("Verifying authentication response with:", {
        response: cred,
        expectedChallenge: clientData.challenge,
        expectedOrigin: c.req.header("origin"),
        expectedRPID: RP_ID,
        authenticator: user.value.credentials[cred.id]
    })

    const verification = await verifyAuthenticationResponse({
        response: cred,
        expectedChallenge: clientData.challenge,
        expectedOrigin: c.req.header("origin")!, //! Allow from any origin
        expectedRPID: RP_ID,
        authenticator: user.value.credentials[cred.id]
    })

    console.log("Verification result:", verification)

    if (verification.verified) {
        const { newCounter } = verification.authenticationInfo

        await kv.delete(["challenges", clientData.challenge])

        const newUser = user.value
        newUser.credentials[cred.id].counter = newCounter

        await kv.set(["users", userId], newUser)

        await setSignedCookie(c, "token", await generateJWT(userId), SECRET, {
            httpOnly: true,
            secure: true,
            sameSite: "Strict",
            path: "/",
            maxAge: 600_000
        })

        const existingDummySignature = await kv.get<string>([
            "dummySignature",
            userId
        ])
        if (existingDummySignature.value) {
            console.log("Dummy signature already exists for userId:", userId)
            return c.json(verification)
        }
        const signature = cred.response.signature
        const authenticatorData = cred.response.authenticatorData

        const authenticatorDataHex = uint8ArrayToHexString(
            b64ToBytes(authenticatorData)
        )
        const signatureHex = uint8ArrayToHexString(b64ToBytes(signature))
        const { r, s } = splitECDSASignature(signatureHex)
        const { beforeT, beforeChallenge } = findQuoteIndices(clientDataJSON)

        const dummySignature = encodeAbiParameters(
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
                beforeChallenge as bigint,
                beforeT as bigint,
                BigInt(r),
                BigInt(s)
            ]
        )

        console.log("dummySignature", dummySignature)
        kv.set(["dummySignature", userId], dummySignature)

        return c.json(verification)
    }
    console.log("Verification failed for user:", userId)

    return c.text("Unauthorized", 401)
})

app.post("/sign-initiate", async (c) => {
    const { data } = await c.req.json<{ data: string }>()
    const token = await getSignedCookie(c, SECRET, "token")
    if (!token) return new Response("Unauthorized", { status: 401 })

    const result = await verifyJWT(token)
    const user = await kv.get<User>(["users", result.payload.userId as string])
    if (!user.value) return new Response("Unauthorized", { status: 401 })

    const credentialsArray = Object.values(user.value.credentials)

    console.log("challenge data", data)

    // Utility function to convert hex string to Uint8Array
    function hexStringToUint8Array(hexString: string): Uint8Array {
        hexString = hexString.startsWith("0x") ? hexString.slice(2) : hexString
        const byteArray = new Uint8Array(hexString.length / 2)
        for (let i = 0; i < hexString.length; i += 2) {
            byteArray[i / 2] = parseInt(hexString.substring(i, i + 2), 16)
        }
        return byteArray
    }

    // Convert data (hex string) to Uint8Array
    const dataUint8Array = hexStringToUint8Array(data)

    const options = await generateAuthenticationOptions({
        challenge: dataUint8Array,
        userVerification: "required",
        rpID: RP_ID,
        allowCredentials: credentialsArray.map((cred) => ({
            id: cred.credentialID,
            type: "public-key"
        }))
    })

    await kv.set(["challenges", options.challenge], data, {
        expireIn: CHALLENGE_TTL
    })

    console.log("options challenge", options.challenge)

    return c.json(options)
})

app.post("/sign-verify", async (c) => {
    const { cred } = await c.req.json<{ cred: AuthenticationResponseJSON }>()
    const clientData = JSON.parse(atob(cred.response.clientDataJSON))
    const challenge = await kv.get<string>(["challenges", clientData.challenge])
    if (!challenge.value) return c.text("Invalid challenge", 400)

    const user = await kv.get<User>([
        "users",
        cred.response.userHandle as string
    ])
    if (!user.value) return c.text("Unauthorized", 401)

    const verification = await verifyAuthenticationResponse({
        response: cred,
        expectedChallenge: clientData.challenge,
        expectedOrigin: c.req.header("origin")!,
        expectedRPID: RP_ID,
        authenticator: user.value.credentials[cred.id]
    })

    if (verification.verified) {
        await kv.delete(["challenges", clientData.challenge])
        const signature = cred.response.signature
        const publicKey = user.value.credentials[cred.id].credentialPublicKey
        const publicKeyBase64 = btoa(
            String.fromCharCode(...new Uint8Array(publicKey.buffer))
        )
        console.log("publicKeyBase64", publicKeyBase64)
        const authenticatorData = cred.response.authenticatorData
        return c.json({
            success: true,
            signedData: challenge.value,
            signature,
            authenticatorData,
            publicKeyBase64
        })
    } else {
        return c.text("Unauthorized", 401)
    }
})

app.get("/private", async (c) => {
    const token = await getSignedCookie(c, SECRET, "token")
    if (!token) return new Response("Unauthorized", { status: 401 })
    console.log({ token })

    const result = await verifyJWT(token)
    console.log({ result })

    const user = await kv.get<User>(["users", result.payload.userId as string])
    if (!user.value) return new Response("Unauthorized", { status: 401 })

    return c.json({
        id: result.payload.userId,
        username: user.value.username || "Anon",
        data: user.value.data
    })
})

Bun.serve({
    port: 8080, // defaults to $BUN_PORT, $PORT, $NODE_PORT otherwise 3000
    fetch: app.fetch
})
