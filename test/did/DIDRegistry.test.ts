import { expect } from "chai";
import hre from "hardhat";

describe("Smoke test — toolchain", () => {
  it("should deploy the sample Lock contract and return a valid non-null address", async () => {
    const ONE_YEAR = 365 * 24 * 60 * 60;
    const unlockTime = Math.floor(Date.now() / 1000) + ONE_YEAR;
    const Lock = await hre.ethers.getContractFactory("Lock");
    const lock = await Lock.deploy(unlockTime, { value: hre.ethers.parseEther("0.001") });
    await lock.waitForDeployment();

    const address = await lock.getAddress();
    const receipt = await hre.ethers.provider.getTransactionReceipt(
      lock.deploymentTransaction()!.hash
    );

    expect(address).to.not.equal(hre.ethers.ZeroAddress);
    expect(receipt?.status).to.equal(1);
  });
});
