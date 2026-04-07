import { expect } from "chai";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { ethers } from "hardhat";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

// ─── constants ────────────────────────────────────────────────────────────────

const DID            = "did:example:123";
const VM_ID          = `${DID}#key-1`;
const SERVICE_ID     = `${DID}#service-1`;
const CONTROLLER_DID = "did:example:controller";

// ─── helpers ──────────────────────────────────────────────────────────────────

function encodeAddr(addr: string): string {
  return ethers.AbiCoder.defaultAbiCoder().encode(["address"], [addr]);
}

function makeDoc(signerAddr: string) {
  return {
    id: DID,
    controller: [CONTROLLER_DID],
    verificationMethods: [
      {
        id: VM_ID,
        controller: DID,
        keyType: "EcdsaSecp256k1RecoveryMethod2020",
        publicKeyMultibase: encodeAddr(signerAddr),
      },
    ],
    authentication: [VM_ID],
    services: [
      { id: SERVICE_ID, serviceType: "LinkedDomains", serviceEndpoint: "https://example.com" },
    ],
  };
}

// Hash types that match abi.encodePacked in each contract function
function h(types: string[], values: unknown[]): string {
  return ethers.keccak256(ethers.solidityPacked(types, values));
}

// signer.signMessage(bytes) prepends "\x19Ethereum Signed Message:\n32" — matches ecrecover in contract
async function sign(signer: HardhatEthersSigner, hash: string) {
  return signer.signMessage(ethers.getBytes(hash));
}

// One signing helper per contract function, mirroring its exact payloadHash construction
const sig = {
  create:           (s: HardhatEthersSigner, did: string, nonce: bigint) =>
    sign(s, h(["string","uint256"], [did, nonce])),
  deactivate:       (s: HardhatEthersSigner, did: string, nonce: bigint) =>
    sign(s, h(["string","uint256"], [did, nonce])),
  update:           (s: HardhatEthersSigner, did: string, nonce: bigint) =>
    sign(s, h(["string","string","uint256"], [did, "update", nonce])),
  crossContract:    (s: HardhatEthersSigner, did: string, target: string, payload: string, nonce: bigint) =>
    sign(s, h(["string","address","bytes","uint256"], [did, target, payload, nonce])),
  addVM:            (s: HardhatEthersSigner, did: string, methodId: string, nonce: bigint) =>
    sign(s, h(["string","string","string","uint256"], [did, "addVerificationMethod", methodId, nonce])),
  removeVM:         (s: HardhatEthersSigner, did: string, methodId: string, nonce: bigint) =>
    sign(s, h(["string","string","string","uint256"], [did, "removeVerificationMethod", methodId, nonce])),
  addService:       (s: HardhatEthersSigner, did: string, serviceId: string, nonce: bigint) =>
    sign(s, h(["string","string","string","uint256"], [did, "addService", serviceId, nonce])),
  removeService:    (s: HardhatEthersSigner, did: string, serviceId: string, nonce: bigint) =>
    sign(s, h(["string","string","string","uint256"], [did, "removeService", serviceId, nonce])),
  addController:    (s: HardhatEthersSigner, did: string, ctrl: string, nonce: bigint) =>
    sign(s, h(["string","string","string","uint256"], [did, "addController", ctrl, nonce])),
  removeController: (s: HardhatEthersSigner, did: string, ctrl: string, nonce: bigint) =>
    sign(s, h(["string","string","string","uint256"], [did, "removeController", ctrl, nonce])),
  addAuth:          (s: HardhatEthersSigner, did: string, methodId: string, nonce: bigint) =>
    sign(s, h(["string","string","string","uint256"], [did, "addAuthentication", methodId, nonce])),
  removeAuth:       (s: HardhatEthersSigner, did: string, methodId: string, nonce: bigint) =>
    sign(s, h(["string","string","string","uint256"], [did, "removeAuthentication", methodId, nonce])),
};

// ─── suite ────────────────────────────────────────────────────────────────────

describe("DID Registry", function () {
  let registry: any;
  let owner: HardhatEthersSigner;
  let other: HardhatEthersSigner;

  beforeEach(async function () {
    [owner, other] = await ethers.getSigners();
    registry = await (await ethers.getContractFactory("didController")).deploy();
  });

  async function createDid() {
    const nonce = await registry.nonces(DID);
    await registry.createDid(makeDoc(owner.address), await sig.create(owner, DID, nonce), owner.address);
  }

  // ────────────────────────────────────────────────────────────────────────────
  // DID format validation (authzXcc.go:199 — 3 colon-separated segments)
  // ────────────────────────────────────────────────────────────────────────────
  describe("DID format validation", function () {
    async function tryCreate(did: string) {
      const doc   = { ...makeDoc(owner.address), id: did };
      const nonce = await registry.nonces(did);
      const s     = await sig.create(owner, did, nonce);
      return registry.createDid(doc, s, owner.address);
    }

    it("accepts did:orcl:uuid format", async function () {
      const orclDid = "did:orcl:550e8400-e29b-41d4-a716-446655440000";
      const doc     = { ...makeDoc(owner.address), id: orclDid };
      const nonce   = await registry.nonces(orclDid);
      const s       = await sig.create(owner, orclDid, nonce);
      await expect(registry.createDid(doc, s, owner.address)).to.not.be.reverted;
    });

    it("accepts any string with exactly 2 colons", async function () {
      await expect(tryCreate("did:example:123")).to.not.be.reverted;
    });

    it("reverts InvalidDidFormat for empty string", async function () {
      await expect(tryCreate("")).to.be.revertedWithCustomError(registry, "InvalidDidFormat");
    });

    it("reverts InvalidDidFormat for only 1 colon (2 segments)", async function () {
      await expect(tryCreate("did:example")).to.be.revertedWithCustomError(registry, "InvalidDidFormat");
    });

    it("reverts InvalidDidFormat for 3 colons (4 segments)", async function () {
      await expect(tryCreate("did:orcl:uuid:extra")).to.be.revertedWithCustomError(registry, "InvalidDidFormat");
    });

    it("reverts InvalidDidFormat in updateDid as well", async function () {
      await createDid();
      const badDoc = { ...makeDoc(owner.address), id: "bad-format" };
      const nonce  = await registry.nonces(DID);
      const s      = await sig.update(owner, DID, nonce);
      // updateDid validates doc.id — bad-format has 0 colons
      await expect(registry.updateDid(badDoc, s, owner.address))
        .to.be.revertedWithCustomError(registry, "InvalidDidFormat");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("createDid", function () {
    it("returns the DID id", async function () {
      const nonce = await registry.nonces(DID);
      const s     = await sig.create(owner, DID, nonce);
      expect(await registry.createDid.staticCall(makeDoc(owner.address), s, owner.address)).to.equal(DID);
    });

    it("stores all nested document fields", async function () {
      await createDid();
      const [doc] = await registry.resolve(DID);
      expect(doc.verificationMethods[0].id).to.equal(VM_ID);
      expect(doc.services[0].id).to.equal(SERVICE_ID);
      expect(doc.authentication[0]).to.equal(VM_ID);
      expect(doc.controller[0]).to.equal(CONTROLLER_DID);
    });

    it("emits DidCreated", async function () {
      const nonce = await registry.nonces(DID);
      const s     = await sig.create(owner, DID, nonce);
      await expect(registry.createDid(makeDoc(owner.address), s, owner.address))
        .to.emit(registry, "DidCreated").withArgs(DID, anyValue);
    });

    it("increments nonce to 1", async function () {
      await createDid();
      expect(await registry.nonces(DID)).to.equal(1n);
    });

    it("reverts if DID already exists", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      const s     = await sig.create(owner, DID, nonce);
      await expect(registry.createDid(makeDoc(owner.address), s, owner.address))
        .to.be.revertedWithCustomError(registry, "DocumentAlreadyExists");
    });

    it("reverts on wrong signer", async function () {
      const nonce = await registry.nonces(DID);
      const s     = await sig.create(other, DID, nonce); // signed by other, claimed as owner
      await expect(registry.createDid(makeDoc(owner.address), s, owner.address))
        .to.be.revertedWith("Invalid Signature");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("resolve", function () {
    it("returns document and metadata for an active DID", async function () {
      await createDid();
      const [doc, meta] = await registry.resolve(DID);
      expect(doc.id).to.equal(DID);
      expect(meta.deactivated).to.equal(false);
      expect(meta.created).to.be.gt(0n);
    });

    it("reverts for an unregistered DID", async function () {
      await expect(registry.resolve("did:unknown:999"))
        .to.be.revertedWithCustomError(registry, "DocumentNotFound");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("dereferenceVerificationMethod", function () {
    it("returns the VerificationMethod by fragment ID", async function () {
      await createDid();
      const vm = await registry.dereferenceVerificationMethod(DID, VM_ID);
      expect(vm.id).to.equal(VM_ID);
      expect(vm.keyType).to.equal("EcdsaSecp256k1RecoveryMethod2020");
    });

    it("reverts if DID not found", async function () {
      await expect(registry.dereferenceVerificationMethod("did:unknown:999", VM_ID))
        .to.be.revertedWithCustomError(registry, "DocumentNotFound");
    });

    it("reverts if fragment not found", async function () {
      await createDid();
      await expect(registry.dereferenceVerificationMethod(DID, `${DID}#nonexistent`))
        .to.be.revertedWithCustomError(registry, "FragmentNotFound");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("updateDid", function () {
    it("replaces all document fields and emits DidUpdated", async function () {
      await createDid();
      const newVMId    = `${DID}#key-2`;
      const updatedDoc = {
        id: DID,
        controller: ["did:example:new-controller"],
        verificationMethods: [
          { id: newVMId, controller: DID, keyType: "Ed25519VerificationKey2020", publicKeyMultibase: encodeAddr(owner.address) },
        ],
        authentication: [newVMId],
        services: [],
      };
      const nonce = await registry.nonces(DID);
      await expect(registry.updateDid(updatedDoc, await sig.update(owner, DID, nonce), owner.address))
        .to.emit(registry, "DidUpdated");
      const [doc] = await registry.resolve(DID);
      expect(doc.verificationMethods[0].id).to.equal(newVMId);
      expect(doc.controller[0]).to.equal("did:example:new-controller");
      expect(doc.services.length).to.equal(0);
    });

    it("reverts if DID is not active", async function () {
      const nonce = await registry.nonces(DID);
      await expect(registry.updateDid(makeDoc(owner.address), await sig.update(owner, DID, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "UnauthorizedCaller");
    });

    it("reverts on wrong signer", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.updateDid(makeDoc(owner.address), await sig.update(other, DID, nonce), owner.address))
        .to.be.revertedWith("Invalid Signature");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("deactivateDid", function () {
    it("sets state to Deactivated and emits DidDeactivated", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.deactivateDid(DID, await sig.deactivate(owner, DID, nonce), owner.address))
        .to.emit(registry, "DidDeactivated").withArgs(DID, anyValue);
      expect(await registry.getDidState(DID)).to.equal(2n);
    });

    it("reverts if DID is not active", async function () {
      const nonce = await registry.nonces(DID);
      await expect(registry.deactivateDid(DID, await sig.deactivate(owner, DID, nonce), owner.address))
        .to.be.revertedWith("DID is not active");
    });

    it("reverts on wrong signer", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.deactivateDid(DID, await sig.deactivate(other, DID, nonce), owner.address))
        .to.be.revertedWith("Invalid Signature");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("getDidState", function () {
    it("returns 0 (Unregistered) for unknown DID", async function () {
      expect(await registry.getDidState("did:unknown:0")).to.equal(0n);
    });

    it("returns 1 (Active) after creation", async function () {
      await createDid();
      expect(await registry.getDidState(DID)).to.equal(1n);
    });

    it("returns 2 (Deactivated) after deactivation", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await registry.deactivateDid(DID, await sig.deactivate(owner, DID, nonce), owner.address);
      expect(await registry.getDidState(DID)).to.equal(2n);
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("executeCrossContract", function () {
    let target: any;
    let targetAddr: string;
    let payload: string;

    beforeEach(async function () {
      target     = await (await ethers.getContractFactory("MockTarget")).deploy();
      targetAddr = await target.getAddress();
      payload    = target.interface.encodeFunctionData("setValue", [42n]);
    });

    it("calls the target and mutates its state", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await registry.executeCrossContract(DID, targetAddr, payload, await sig.crossContract(owner, DID, targetAddr, payload, nonce), owner.address);
      expect(await target.value()).to.equal(42n);
    });

    it("emits CrossContractExecuted", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.executeCrossContract(DID, targetAddr, payload, await sig.crossContract(owner, DID, targetAddr, payload, nonce), owner.address))
        .to.emit(registry, "CrossContractExecuted").withArgs(DID, targetAddr, true);
    });

    it("reverts if DID is not active", async function () {
      const nonce = await registry.nonces(DID);
      await expect(registry.executeCrossContract(DID, targetAddr, payload, await sig.crossContract(owner, DID, targetAddr, payload, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "UnauthorizedCaller");
    });

    it("reverts on zero-address target", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.executeCrossContract(DID, ethers.ZeroAddress, payload, await sig.crossContract(owner, DID, ethers.ZeroAddress, payload, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "InvalidPayload");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("addVerificationMethod", function () {
    const NEW_VM_ID = `${DID}#key-2`;
    const newVM     = (addr: string) => ({
      id: NEW_VM_ID, controller: DID, keyType: "EcdsaSecp256k1RecoveryMethod2020", publicKeyMultibase: encodeAddr(addr),
    });

    it("appends the method and emits DidUpdated", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.addVerificationMethod(DID, newVM(owner.address), await sig.addVM(owner, DID, NEW_VM_ID, nonce), owner.address))
        .to.emit(registry, "DidUpdated");
      const [doc] = await registry.resolve(DID);
      expect(doc.verificationMethods.length).to.equal(2);
      expect(doc.verificationMethods[1].id).to.equal(NEW_VM_ID);
    });

    it("reverts on duplicate method ID", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.addVerificationMethod(DID, { ...newVM(owner.address), id: VM_ID }, await sig.addVM(owner, DID, VM_ID, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "MethodAlreadyExists");
    });

    it("reverts if DID is not active", async function () {
      const nonce = await registry.nonces(DID);
      await expect(registry.addVerificationMethod(DID, newVM(owner.address), await sig.addVM(owner, DID, NEW_VM_ID, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "UnauthorizedCaller");
    });

    it("reverts on wrong signer", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.addVerificationMethod(DID, newVM(owner.address), await sig.addVM(other, DID, NEW_VM_ID, nonce), owner.address))
        .to.be.revertedWith("Invalid Signature");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("removeVerificationMethod", function () {
    it("removes the method and emits DidUpdated", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.removeVerificationMethod(DID, VM_ID, await sig.removeVM(owner, DID, VM_ID, nonce), owner.address))
        .to.emit(registry, "DidUpdated");
      const [doc] = await registry.resolve(DID);
      expect(doc.verificationMethods.length).to.equal(0);
    });

    it("reverts if method not found", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.removeVerificationMethod(DID, `${DID}#nonexistent`, await sig.removeVM(owner, DID, `${DID}#nonexistent`, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "MethodNotFound");
    });

    it("reverts if DID is not active", async function () {
      const nonce = await registry.nonces(DID);
      await expect(registry.removeVerificationMethod(DID, VM_ID, await sig.removeVM(owner, DID, VM_ID, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "UnauthorizedCaller");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("addService", function () {
    const NEW_SVC = `${DID}#service-2`;
    const newSvc  = () => ({ id: NEW_SVC, serviceType: "DIDCommMessaging", serviceEndpoint: "https://example.com/didcomm" });

    it("appends the service and emits DidUpdated", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.addService(DID, newSvc(), await sig.addService(owner, DID, NEW_SVC, nonce), owner.address))
        .to.emit(registry, "DidUpdated");
      const [doc] = await registry.resolve(DID);
      expect(doc.services.length).to.equal(2);
      expect(doc.services[1].id).to.equal(NEW_SVC);
    });

    it("reverts on duplicate service ID", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.addService(DID, { ...newSvc(), id: SERVICE_ID }, await sig.addService(owner, DID, SERVICE_ID, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "ServiceAlreadyExists");
    });

    it("reverts if DID is not active", async function () {
      const nonce = await registry.nonces(DID);
      await expect(registry.addService(DID, newSvc(), await sig.addService(owner, DID, NEW_SVC, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "UnauthorizedCaller");
    });

    it("reverts on wrong signer", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.addService(DID, newSvc(), await sig.addService(other, DID, NEW_SVC, nonce), owner.address))
        .to.be.revertedWith("Invalid Signature");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("removeService", function () {
    it("removes the service and emits DidUpdated", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.removeService(DID, SERVICE_ID, await sig.removeService(owner, DID, SERVICE_ID, nonce), owner.address))
        .to.emit(registry, "DidUpdated");
      const [doc] = await registry.resolve(DID);
      expect(doc.services.length).to.equal(0);
    });

    it("reverts if service not found", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.removeService(DID, `${DID}#nonexistent`, await sig.removeService(owner, DID, `${DID}#nonexistent`, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "ServiceNotFound");
    });

    it("reverts if DID is not active", async function () {
      const nonce = await registry.nonces(DID);
      await expect(registry.removeService(DID, SERVICE_ID, await sig.removeService(owner, DID, SERVICE_ID, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "UnauthorizedCaller");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("addController", function () {
    const NEW_CTRL = "did:example:new-controller";

    it("appends the controller and emits DidUpdated", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.addController(DID, NEW_CTRL, await sig.addController(owner, DID, NEW_CTRL, nonce), owner.address))
        .to.emit(registry, "DidUpdated");
      const [doc] = await registry.resolve(DID);
      expect(doc.controller).to.include(NEW_CTRL);
    });

    it("reverts on duplicate controller", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.addController(DID, CONTROLLER_DID, await sig.addController(owner, DID, CONTROLLER_DID, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "ControllerAlreadyExists");
    });

    it("reverts if DID is not active", async function () {
      const nonce = await registry.nonces(DID);
      await expect(registry.addController(DID, NEW_CTRL, await sig.addController(owner, DID, NEW_CTRL, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "UnauthorizedCaller");
    });

    it("reverts on wrong signer", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.addController(DID, NEW_CTRL, await sig.addController(other, DID, NEW_CTRL, nonce), owner.address))
        .to.be.revertedWith("Invalid Signature");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("removeController", function () {
    it("removes the controller and emits DidUpdated", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.removeController(DID, CONTROLLER_DID, await sig.removeController(owner, DID, CONTROLLER_DID, nonce), owner.address))
        .to.emit(registry, "DidUpdated");
      const [doc] = await registry.resolve(DID);
      expect(doc.controller).to.not.include(CONTROLLER_DID);
    });

    it("reverts if controller not found", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.removeController(DID, "did:example:nonexistent", await sig.removeController(owner, DID, "did:example:nonexistent", nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "ControllerNotFound");
    });

    it("reverts if DID is not active", async function () {
      const nonce = await registry.nonces(DID);
      await expect(registry.removeController(DID, CONTROLLER_DID, await sig.removeController(owner, DID, CONTROLLER_DID, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "UnauthorizedCaller");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("addAuthentication", function () {
    const NEW_AUTH = `${DID}#key-3`;

    it("appends the method reference and emits DidUpdated", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.addAuthentication(DID, NEW_AUTH, await sig.addAuth(owner, DID, NEW_AUTH, nonce), owner.address))
        .to.emit(registry, "DidUpdated");
      const [doc] = await registry.resolve(DID);
      expect(doc.authentication).to.include(NEW_AUTH);
    });

    it("reverts on duplicate authentication entry", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.addAuthentication(DID, VM_ID, await sig.addAuth(owner, DID, VM_ID, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "AuthenticationAlreadyExists");
    });

    it("reverts if DID is not active", async function () {
      const nonce = await registry.nonces(DID);
      await expect(registry.addAuthentication(DID, NEW_AUTH, await sig.addAuth(owner, DID, NEW_AUTH, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "UnauthorizedCaller");
    });

    it("reverts on wrong signer", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.addAuthentication(DID, NEW_AUTH, await sig.addAuth(other, DID, NEW_AUTH, nonce), owner.address))
        .to.be.revertedWith("Invalid Signature");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  describe("removeAuthentication", function () {
    it("removes the entry and emits DidUpdated", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.removeAuthentication(DID, VM_ID, await sig.removeAuth(owner, DID, VM_ID, nonce), owner.address))
        .to.emit(registry, "DidUpdated");
      const [doc] = await registry.resolve(DID);
      expect(doc.authentication).to.not.include(VM_ID);
    });

    it("reverts if entry not found", async function () {
      await createDid();
      const nonce = await registry.nonces(DID);
      await expect(registry.removeAuthentication(DID, `${DID}#nonexistent`, await sig.removeAuth(owner, DID, `${DID}#nonexistent`, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "AuthenticationNotFound");
    });

    it("reverts if DID is not active", async function () {
      const nonce = await registry.nonces(DID);
      await expect(registry.removeAuthentication(DID, VM_ID, await sig.removeAuth(owner, DID, VM_ID, nonce), owner.address))
        .to.be.revertedWithCustomError(registry, "UnauthorizedCaller");
    });
  });

  // ────────────────────────────────────────────────────────────────────────────
  // verifyRelationship — tested via DidVerificationHarness (internal library)
  // ────────────────────────────────────────────────────────────────────────────
  describe("verifyRelationship", function () {
    let harness: any;

    beforeEach(async function () {
      harness = await (await ethers.getContractFactory("DidVerificationHarness")).deploy();
      await harness.setDoc(makeDoc(owner.address));
    });

    it("returns true when signer address is in the authentication relationship", async function () {
      expect(await harness.verifyRelationship("authentication", owner.address)).to.equal(true);
    });

    it("returns false when signer is not in the relationship", async function () {
      expect(await harness.verifyRelationship("authentication", other.address)).to.equal(false);
    });

    it("reverts for unsupported relationship type", async function () {
      await expect(harness.verifyRelationship("assertionMethod", owner.address))
        .to.be.revertedWithCustomError(harness, "UnsupportedRelationshipType");
    });

    it("findVerificationMethod returns the correct method", async function () {
      const vm = await harness.findVerificationMethod(VM_ID);
      expect(vm.id).to.equal(VM_ID);
    });

    it("findVerificationMethod reverts for unknown ID", async function () {
      await expect(harness.findVerificationMethod(`${DID}#nonexistent`))
        .to.be.revertedWithCustomError(harness, "VerificationMethodNotFound");
    });
  });
});
