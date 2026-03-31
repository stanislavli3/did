// SPDX-License-Identifier: Apache-2.0
// Deploys didController (the top-level DID registry contract) to the configured network.
import hre, { ethers } from "hardhat";
import * as fs from "fs";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Account balance:", (await deployer.provider.getBalance(deployer.address)).toString());

  const DidController = await ethers.getContractFactory("didController");
  const didController = await DidController.deploy();
  await didController.waitForDeployment();

  const address = await didController.getAddress();
  const tx = didController.deploymentTransaction();
  const receipt = await deployer.provider.getTransactionReceipt(tx!.hash);

  console.log("didController deployed to:", address);
  console.log("Transaction hash:", tx?.hash);
  console.log("Receipt status:", receipt?.status); // 1 = success

  const output = {
    network: hre.network.name,
    didController: address,
    deployedAt: new Date().toISOString(),
    txHash: tx?.hash,
  };
  fs.writeFileSync("deployed-addresses.json", JSON.stringify(output, null, 2));
  console.log("Addresses written to deployed-addresses.json");
}

main().catch((err) => { console.error(err); process.exit(1); });
