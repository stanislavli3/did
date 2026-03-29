// SPDX-License-Identifier: Apache-2.0
// Smoke-test deploy: deploys Lock.sol to verify the toolchain works end-to-end.
// Full DIDRegistry deploy implemented in Issue #3.
import hre, { ethers } from "hardhat";
import * as fs from "fs";

async function main() {
  const [deployer] = await ethers.getSigners();
  console.log("Deploying with account:", deployer.address);
  console.log("Account balance:", (await deployer.provider.getBalance(deployer.address)).toString());

  const ONE_YEAR = 365 * 24 * 60 * 60;
  const unlockTime = Math.floor(Date.now() / 1000) + ONE_YEAR;

  const Lock = await ethers.getContractFactory("Lock");
  const lock = await Lock.deploy(unlockTime, { value: ethers.parseEther("0.001") });
  await lock.waitForDeployment();

  const address = await lock.getAddress();
  const tx = lock.deploymentTransaction();
  const receipt = await deployer.provider.getTransactionReceipt(tx!.hash);

  console.log("Lock deployed to:", address);
  console.log("Transaction hash:", tx?.hash);
  console.log("Receipt status:", receipt?.status); // 1 = success

  const output = {
    network: hre.network.name,
    Lock: address,
    deployedAt: new Date().toISOString(),
    txHash: tx?.hash,
  };
  fs.writeFileSync("deployed-addresses.json", JSON.stringify(output, null, 2));
  console.log("Addresses written to deployed-addresses.json");
}

main().catch((err) => { console.error(err); process.exit(1); });
