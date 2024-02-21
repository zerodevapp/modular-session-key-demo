import { useState } from "react"
import { Chain, Transport, pad, zeroAddress, hashMessage, Hex } from "viem"
import "./App.css"
import {
    getEntryPoint,
    getKernelAccountClient,
    getZeroDevPaymasterClient,
    loginToWebAuthnKernelAccount,
    registerWebAuthnKernelAccount,
    createWebAuthnModularKernelAccount,
} from "./utils"
import { KernelAccountClient, KernelSmartAccount } from "@zerodev/sdk"
import { WebAuthnMode } from "@zerodev/modular-permission/signers"
import { getAction } from "permissionless"
import { readContract } from "viem/actions"
import { MockRequestorAbi } from "./abis/MockRequestorAbi"

const projectId = "06cf2ab0-9a15-4049-b826-c6a61b62ef17"
// const URL = `http://localhost:4003/projects/${projectId}/passkey`
// const URL = 'http://localhost:8080'
const url = `https://passkeys.zerodev.app/api/v2/${projectId}`

let account
let kernelClient: KernelAccountClient<Transport, Chain, KernelSmartAccount>

function App() {
    const [status, setStatus] = useState<string>("")
    const [name, setName] = useState<string>("")
    const [signature, setSignature] = useState<Hex>("0x")

    const handleRegister = async () => {
        account = await registerWebAuthnKernelAccount(
            name,
            `${url}/register/options`,
            `${url}/register/verify`,
            `${url}/sign-initiate`,
            `${url}/sign-verify`
        )
        kernelClient = await getKernelAccountClient({
            account,
            sponsorUserOperation: async ({ userOperation }) => {
                const zerodevPaymaster = getZeroDevPaymasterClient()
                const entryPoint = getEntryPoint()
                return zerodevPaymaster.sponsorUserOperation({
                    userOperation,
                    entryPoint,
                })
            },
        })

        console.log("account", account)
        setStatus(`Registered: ${JSON.stringify(account)}`)
    }

    const handleModularRegister = async () => {
        account = await createWebAuthnModularKernelAccount(
            name,
            WebAuthnMode.Register,
            url
        )
        kernelClient = await getKernelAccountClient({
            account,
            sponsorUserOperation: async ({ userOperation }) => {
                const zerodevPaymaster = getZeroDevPaymasterClient()
                const entryPoint = getEntryPoint()
                return zerodevPaymaster.sponsorUserOperation({
                    userOperation,
                    entryPoint,
                })
            },
        })

        console.log("Modular account", account)
        setStatus(`Registered modular account: ${JSON.stringify(account)}`)
    }

    const handleModularLogin = async () => {
        account = await createWebAuthnModularKernelAccount(
            name,
            WebAuthnMode.Login,
            url
        )
        kernelClient = await getKernelAccountClient({
            account,
            sponsorUserOperation: async ({ userOperation }) => {
                const zerodevPaymaster = getZeroDevPaymasterClient()
                const entryPoint = getEntryPoint()
                return zerodevPaymaster.sponsorUserOperation({
                    userOperation,
                    entryPoint,
                })
            },
        })

        console.log("Modular account", account)
        setStatus(`Registered modular account: ${JSON.stringify(account)}`)
    }

    const handleSignMessage = async () => {
        const response = await kernelClient.signMessage({
            message: "Hello, world!",
        })
        setStatus(`Signature: ${JSON.stringify(response)}`)
        setSignature(response)
    }

    const verifySignature = async () => {
        const response = await getAction(
            kernelClient.account.client,
            readContract
        )({
            abi: MockRequestorAbi,
            address: "0x67e0a05806A54f6C2162a91810BD50eFe28e0460",
            functionName: "verifySignature",
            args: [
                kernelClient.account.address,
                hashMessage("Hello, world!"),
                signature,
            ],
        })
        console.log("Signature verified response: ", response)
        setStatus(`Signature verified: ${JSON.stringify(response)}`)
    }

    const handleLogin = async () => {
        account = await loginToWebAuthnKernelAccount(
            `${url}/login/options`,
            `${url}/login/verify`,
            `${url}/sign-initiate`,
            `${url}/sign-verify`
        )

        kernelClient = await getKernelAccountClient({
            account,
            sponsorUserOperation: async ({ userOperation }) => {
                const zerodevPaymaster = getZeroDevPaymasterClient()
                const entryPoint = getEntryPoint()
                return zerodevPaymaster.sponsorUserOperation({
                    userOperation,
                    entryPoint,
                })
            },
        })

        console.log("account", account)
        setStatus(`Sign in: ${JSON.stringify(account)}`)
    }

    const handleSendUserOp = async () => {
        const response = await kernelClient.sendUserOperation({
            userOperation: {
                callData: await kernelClient.account.encodeCallData({
                    to: zeroAddress,
                    value: 0n,
                    data: pad("0x", { size: 4 }),
                }),
                // maxPriorityFeePerGas: 2575000000n,
                // maxFeePerGas: 2575000000n,
                // verificationGasLimit: 700000n,
            },
        })
        setStatus(`Sent UserOp: ${JSON.stringify(response)}`)
    }

    return (
        <>
            <h1>WebAuthn Demo</h1>
            <div className="card">
                <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="Enter your name"
                />
                <div>
                    <button onClick={handleRegister}>Register</button>
                    <button onClick={handleLogin}>Login</button>
                    <button onClick={handleModularRegister}>
                        Modular Register
                    </button>
                    <button onClick={handleModularLogin}>Modular Login</button>
                    <button onClick={handleSendUserOp}>Send UserOp</button>
                    <button onClick={handleSignMessage}>Sign Message</button>
                    <button onClick={verifySignature}>Verify Message</button>
                </div>
                <p>Status: {status}</p>
            </div>
        </>
    )
}

export default App
