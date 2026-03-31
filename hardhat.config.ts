import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";
import * as dotenv from "dotenv";
dotenv.config();

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      viaIR: true,
    },
  },
  networks: {
    localBasu: {
      url: process.env.LOCAL_BESU_RPC_URL || "http://localhost:8545",
      accounts: process.env.LOCAL_BESU_PRIVATE_KEY
        ? [process.env.LOCAL_BESU_PRIVATE_KEY]
        : [],
      httpHeaders: { "Content-Type": "application/json" },
      // TLS off for local dev — warning is expected and acceptable
    },
    obp: {
      url: process.env.OBP_BESU_RPC_URL || "",
      accounts: process.env.OBP_PRIVATE_KEY ? [process.env.OBP_PRIVATE_KEY] : [],
      // TLS on for OBP — CA cert configured via NODE_EXTRA_CA_CERTS env var
    },
  },
};

export default config;
