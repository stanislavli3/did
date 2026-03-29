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
      lock.deploymentTransaction()!.hash,
    );

    expect(address).to.not.equal(hre.ethers.ZeroAddress);
    expect(receipt?.status).to.equal(1);
  });
});

describe("DIDRegistry — contract skeleton", () => {
  it("should compile and expose all 4 function signatures in the ABI", async () => {
    const artifact = await hre.artifacts.readArtifact("DIDRegistry");
    const functionNames = artifact.abi
      .filter((x: any) => x.type === "function")
      .map((x: any) => x.name);

    expect(functionNames).to.include("createDID");
    expect(functionNames).to.include("resolveDID");
    expect(functionNames).to.include("updateDID");
    expect(functionNames).to.include("deactivateDID");
  });

  it("should expose all 3 event signatures in the ABI", async () => {
    const artifact = await hre.artifacts.readArtifact("DIDRegistry");
    const eventNames = artifact.abi.filter((x: any) => x.type === "event").map((x: any) => x.name);

    expect(eventNames).to.include("DIDCreated");
    expect(eventNames).to.include("DIDUpdated");
    expect(eventNames).to.include("DIDDeactivated");
  });

  it("should expose REGISTRAR_ROLE and ADMIN_ROLE as public constants in the ABI", async () => {
    const artifact = await hre.artifacts.readArtifact("DIDRegistry");
    const functionNames = artifact.abi
      .filter((x: any) => x.type === "function")
      .map((x: any) => x.name);

    expect(functionNames).to.include("REGISTRAR_ROLE");
    expect(functionNames).to.include("ADMIN_ROLE");
  });

  it("should mark resolveDID as a view function in the ABI", async () => {
    const artifact = await hre.artifacts.readArtifact("DIDRegistry");
    const resolveFn = artifact.abi.find(
      (x: any) => x.type === "function" && x.name === "resolveDID",
    );
    expect(resolveFn).to.not.be.undefined;
    expect(resolveFn.stateMutability).to.equal("view");
  });
});
