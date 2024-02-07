import { useState } from "react"
import { Chain, Transport, zeroAddress } from "viem"
import "./App.css"
import {
    getEntryPoint,
    getKernelAccountClient,
    getZeroDevPaymasterClient,
    loginToWebAuthnKernelAccount,
    registerWebAuthnKernelAccount
} from "./utils"
import { KernelAccountClient, KernelSmartAccount } from "@zerodev/sdk"

let account
let kernelClient: KernelAccountClient<Transport, Chain, KernelSmartAccount>

function App() {
    const [status, setStatus] = useState<string>("")
    const [name, setName] = useState<string>("")
    const [message, setMessage] = useState<string>("")
    const [signature, setSignature] = useState<string>("")
    const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false)
    const [authenticatorData, setAuthenticatorData] = useState<string>("")

    const fetchDummySignature = async (userId: string) => {
        const response = await fetch(
            `http://localhost:8080/dummy-signature/${userId}`
        )
        const result = await response.json()
        return result.dummySignature
    }

    const handleRegister = async () => {
        account = await registerWebAuthnKernelAccount(
            name,
            "http://localhost:8080/register/options",
            "http://localhost:8080/register/verify",
            "http://localhost:8080/sign-initiate",
            "http://localhost:8080/sign-verify"
        )
        kernelClient = await getKernelAccountClient({
            account,
            sponsorUserOperation: async ({ userOperation }) => {
                const zerodevPaymaster = getZeroDevPaymasterClient()
                const entryPoint = getEntryPoint()
                return zerodevPaymaster.sponsorUserOperation({
                    userOperation,
                    entryPoint
                })
            }
        })

        console.log("account", account)
        setStatus(`Registered: ${JSON.stringify(account)}`)
    }

    const handleLogin = async () => {
        account = await loginToWebAuthnKernelAccount(
            "http://localhost:8080/login/options",
            "http://localhost:8080/login/verify",
            "http://localhost:8080/sign-initiate",
            "http://localhost:8080/sign-verify"
        )

        kernelClient = await getKernelAccountClient({
            account,
            sponsorUserOperation: async ({ userOperation }) => {
                const zerodevPaymaster = getZeroDevPaymasterClient()
                const entryPoint = getEntryPoint()
                return zerodevPaymaster.sponsorUserOperation({
                    userOperation,
                    entryPoint
                })
            }
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
                    data: "0x"
                })
                // maxPriorityFeePerGas: 2575000000n,
                // maxFeePerGas: 2575000000n,
                // verificationGasLimit: 700000n
            }
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
                    <button onClick={handleSendUserOp}>Send UserOp</button>
                </div>
                <p>Status: {status}</p>
                {authenticatorData && (
                    <div className="card">
                        <h2>Authenticator Data</h2>
                        <pre>{authenticatorData}</pre>
                    </div>
                )}

                {isAuthenticated && (
                    <div className="card">
                        <p>Authenticated!</p>
                        <div className="input-group">
                            <input
                                key="message-input"
                                type="text"
                                value={message}
                                onChange={(e) => setMessage(e.target.value)}
                                placeholder="Enter your message"
                                className="input"
                            />
                            <div>
                                <button
                                    onClick={handleSignData}
                                    className="button"
                                >
                                    Sign Data
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </>
    )
}

export default App
