export const MockRequestorAbi = [
    {
        type: "function",
        name: "verifySignature",
        inputs: [
            { name: "kernel", type: "address", internalType: "address" },
            { name: "hash", type: "bytes32", internalType: "bytes32" },
            { name: "signature", type: "bytes", internalType: "bytes" },
        ],
        outputs: [{ name: "", type: "bool", internalType: "bool" }],
        stateMutability: "payable",
    },
] as const
