# DID Registry — Hyperledger Besu

Solidity implementation of a DID (Decentralized Identifier) Registry, converted from Hyperledger Fabric chaincode, targeting Hyperledger Besu (OBP/OKE).

**Stack:** Solidity 0.8.24 · Hardhat 2.x + TypeScript · OpenZeppelin · Local Besu via Docker · OBP enterprise Besu

---

## Install

```bash
npm install
```

---

## Compile

```bash
npx hardhat compile
```

---

## Test

```bash
npx hardhat test
```

---

## Deploy

### Local Besu

1. Start your local Besu node (Docker or standalone) on `http://localhost:8545`
2. Copy `.env.example` to `.env` and fill in `LOCAL_BESU_PRIVATE_KEY`
3. Run:

```bash
npx hardhat run scripts/deploy/deployDIDRegistry.ts --network localBasu
```

Expected output: contract address printed to console, `deployed-addresses.json` written.

### OBP Besu

1. Obtain `OBP_BESU_RPC_URL`, `OBP_CHAIN_ID`, and the CA cert file from Nate
2. Fill in `.env` (`OBP_BESU_RPC_URL`, `OBP_PRIVATE_KEY`, `OBP_CHAIN_ID`, `INITIAL_REGISTRAR`)
3. Set the CA cert path:

```bash
export NODE_EXTRA_CA_CERTS=/path/to/obp-ca.crt
```

4. Run:

```bash
npx hardhat run scripts/deploy/deployDIDRegistry.ts --network obp
```

---

## Environment variables

Copy `.env.example` to `.env` and fill in the required values. **Never commit `.env`.**

| Variable | Description |
|---|---|
| `LOCAL_BESU_RPC_URL` | RPC URL for local Besu node (default: `http://localhost:8545`) |
| `LOCAL_BESU_PRIVATE_KEY` | Private key for local deployments |
| `OBP_BESU_RPC_URL` | RPC URL for OBP enterprise Besu |
| `OBP_PRIVATE_KEY` | Private key for OBP deployments |
| `OBP_CHAIN_ID` | Chain ID of the OBP network |
| `INITIAL_REGISTRAR` | Address to grant `REGISTRAR_ROLE` on deploy (defaults to deployer) |
| `NODE_EXTRA_CA_CERTS` | Path to OBP CA cert file (required for OBP TLS) |

---

## Deployed contracts

| Network | Address | Tx hash | Deployed at |
|---|---|---|---|
| *(updated after Issue #3)* | — | — | — |
