import type { KernelValidator } from "@zerodev/sdk/types"
import { createPasskeyValidator } from "./toWebAuthnValidator"

export { createPasskeyValidator, type KernelValidator }

export const WEBAUTHN_VALIDATOR_ADDRESS =
    "0x940c1F08923E22B33d8dFeDC25e5C1Fc369Ee61a"
