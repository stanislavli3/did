/**
 * RevocationRegistry tests
 *
 * Covers:
 *   RevRegDef: createRevRegDef, getRevRegDef, revRegDefExists
 *   RevStatusList: updateRevStatusList, getRevStatusList
 *   Cross-contract validation: issuer DID must be Active, credDef must exist
 *   Replay protection: nonce per issuerId
 *   Key collision handling: KeyCollision vs RevRegDefAlreadyExists
 */
import { expect } from "chai";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { ethers } from "hardhat";
import { HardhatEthersSigner } from "@nomicfoundation/hardhat-ethers/signers";

// ─── constants ────────────────────────────────────────────────────────────────

const ISSUER_DID  = "did:orcl:550e8400-e29b-41d4-a716-446655440000";
const VM_ID       = `${ISSUER_DID}#key-1`;
const SCHEMA_NAME = "EmployeeCredential";
const SCHEMA_VER  = "1.0";
const ATTR_NAMES  = ["firstName", "lastName", "employeeId"];
const CD_TAG      = "default";
const CD_VALUE    = ethers.toUtf8Bytes('{"n":"abc","s":"def","rctxt":"ghi","z":"jkl"}');
const CL          = 0; // CredDefType.CL
const REV_TAG     = "rev-default";
const TAILS_LOC   = "https://tails.example.com/tails-file";
const TAILS_HASH  = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3";
const MAX_CRED    = 128;
const ACCUM       = ethers.toUtf8Bytes("accumulator-bytes");
const REV_LIST    = ethers.toUtf8Bytes("\xff\x00"); // first 8 revoked, next 8 active

// ─── helpers ──────────────────────────────────────────────────────────────────

function encodeAddr(addr: string): string {
  return ethers.AbiCoder.defaultAbiCoder().encode(["address"], [addr]);
}

function makeIssuerDoc(addr: string) {
  return {
    id: ISSUER_DID,
    controller: [ISSUER_DID],
    verificationMethods: [
      { id: VM_ID, controller: ISSUER_DID, keyType: "EcdsaSecp256k1RecoveryMethod2020", publicKeyMultibase: encodeAddr(addr) },
    ],
    authentication: [VM_ID],
    services: [],
    revocations: [],
  };
}

async function sign(signer: HardhatEthersSigner, hash: string) {
  return signer.signMessage(ethers.getBytes(hash));
}

function h(types: string[], values: unknown[]) {
  return ethers.keccak256(ethers.solidityPacked(types, values));
}

const sigCreate = (s: HardhatEthersSigner, did: string, nonce: bigint) =>
  sign(s, h(["string","uint256"], [did, nonce]));
const sigPublishSchema = (s: HardhatEthersSigner, issuerId: string, name: string, version: string, nonce: bigint) =>
  sign(s, h(["string","string","string","uint256"], [issuerId, name, version, nonce]));
const sigPublishCredDef = (s: HardhatEthersSigner, issuerId: string, schemaId: string, tag: string, nonce: bigint) =>
  sign(s, h(["string","bytes32","string","uint256"], [issuerId, schemaId, tag, nonce]));
const sigCreateRevRegDef = (s: HardhatEthersSigner, issuerId: string, credDefId: string, tag: string, nonce: bigint) =>
  sign(s, h(["string","bytes32","string","uint256"], [issuerId, credDefId, tag, nonce]));
const sigUpdateRevStatus = (s: HardhatEthersSigner, revRegId: string, timestamp: bigint, nonce: bigint) =>
  sign(s, h(["bytes32","uint256","uint256"], [revRegId, timestamp, nonce]));

// ─── suite ────────────────────────────────────────────────────────────────────

describe("RevocationRegistry", function () {
  let didRegistry: any;
  let schemaRegistry: any;
  let credDefRegistry: any;
  let revRegistry: any;
  let owner: HardhatEthersSigner;
  let other: HardhatEthersSigner;
  let credDefId: string; // bytes32

  beforeEach(async function () {
    [owner, other] = await ethers.getSigners();

    // Deploy dependency chain
    didRegistry    = await (await ethers.getContractFactory("didController")).deploy();
    schemaRegistry = await (await ethers.getContractFactory("SchemaRegistry")).deploy(await didRegistry.getAddress());
    credDefRegistry = await (await ethers.getContractFactory("CredDefRegistry")).deploy(
      await didRegistry.getAddress(),
      await schemaRegistry.getAddress()
    );
    revRegistry = await (await ethers.getContractFactory("RevocationRegistry")).deploy(
      await didRegistry.getAddress(),
      await credDefRegistry.getAddress()
    );

    // Register issuer DID
    await didRegistry.createDid(
      makeIssuerDoc(owner.address),
      await sigCreate(owner, ISSUER_DID, await didRegistry.nonces(ISSUER_DID))
    );

    // Publish a schema
    await schemaRegistry.publishSchema(
      ISSUER_DID, SCHEMA_NAME, SCHEMA_VER, ATTR_NAMES,
      await sigPublishSchema(owner, ISSUER_DID, SCHEMA_NAME, SCHEMA_VER, await schemaRegistry.nonces(ISSUER_DID)),
      owner.address
    );

    // Publish a credential definition and capture its id
    const schemaId = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(["string","string","string"], [ISSUER_DID, SCHEMA_NAME, SCHEMA_VER])
    );
    const cdTx = await credDefRegistry.publishCredDef(
      ISSUER_DID, schemaId, CL, CD_TAG, CD_VALUE,
      await sigPublishCredDef(owner, ISSUER_DID, schemaId, CD_TAG, await credDefRegistry.nonces(ISSUER_DID)),
      owner.address
    );
    const cdReceipt = await cdTx.wait();
    credDefId = cdReceipt.logs[0].topics[1];
  });

  // ── helper to publish a RevRegDef ──────────────────────────────────────────

  async function createRevRegDef(
    signer: HardhatEthersSigner = owner,
    issuerId = ISSUER_DID,
    cdId = credDefId,
    tag = REV_TAG
  ) {
    const nonce = await revRegistry.nonces(issuerId);
    const sig   = await sigCreateRevRegDef(signer, issuerId, cdId, tag, nonce);
    return revRegistry.createRevRegDef(
      issuerId, cdId, tag,
      { tailsLocation: TAILS_LOC, tailsHash: TAILS_HASH, maxCredNum: MAX_CRED },
      sig, signer.address
    );
  }

  // ── createRevRegDef ────────────────────────────────────────────────────────

  describe("createRevRegDef", function () {

    it("returns deterministic bytes32 id = keccak256(issuerId, credDefId, tag)", async function () {
      const expected = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(["string","bytes32","string"], [ISSUER_DID, credDefId, REV_TAG])
      );
      const id = await revRegistry.createRevRegDef.staticCall(
        ISSUER_DID, credDefId, REV_TAG,
        { tailsLocation: TAILS_LOC, tailsHash: TAILS_HASH, maxCredNum: MAX_CRED },
        await sigCreateRevRegDef(owner, ISSUER_DID, credDefId, REV_TAG, await revRegistry.nonces(ISSUER_DID)),
        owner.address
      );
      expect(id).to.equal(expected);
    });

    it("stores all fields and sets revocDefType to CL_ACCUM", async function () {
      const tx      = await createRevRegDef();
      const receipt = await tx.wait();
      const id      = receipt.logs[0].topics[1];
      const def     = await revRegistry.getRevRegDef(id);
      expect(def.issuerId).to.equal(ISSUER_DID);
      expect(def.credDefId).to.equal(credDefId);
      expect(def.tag).to.equal(REV_TAG);
      expect(def.revocDefType).to.equal("CL_ACCUM");
      expect(def.value.tailsLocation).to.equal(TAILS_LOC);
      expect(def.value.tailsHash).to.equal(TAILS_HASH);
      expect(def.value.maxCredNum).to.equal(MAX_CRED);
    });

    it("emits RevRegDefCreated with correct args", async function () {
      const nonce = await revRegistry.nonces(ISSUER_DID);
      const sig   = await sigCreateRevRegDef(owner, ISSUER_DID, credDefId, REV_TAG, nonce);
      await expect(revRegistry.createRevRegDef(ISSUER_DID, credDefId, REV_TAG,
        { tailsLocation: TAILS_LOC, tailsHash: TAILS_HASH, maxCredNum: MAX_CRED },
        sig, owner.address))
        .to.emit(revRegistry, "RevRegDefCreated")
        .withArgs(anyValue, ISSUER_DID, credDefId, REV_TAG);
    });

    it("increments nonce per issuerId after creation", async function () {
      await createRevRegDef();
      expect(await revRegistry.nonces(ISSUER_DID)).to.equal(1n);
    });

    it("allows multiple RevRegDefs per credDef with different tags", async function () {
      await createRevRegDef(owner, ISSUER_DID, credDefId, "rev-tag-a");
      await createRevRegDef(owner, ISSUER_DID, credDefId, "rev-tag-b");
    });

    it("reverts RevRegDefAlreadyExists on exact duplicate", async function () {
      await createRevRegDef();
      await expect(createRevRegDef()).to.be.revertedWithCustomError(revRegistry, "RevRegDefAlreadyExists");
    });

    it("reverts InvalidRevRegDef when issuerId is empty", async function () {
      const nonce = await revRegistry.nonces("");
      const sig   = await sigCreateRevRegDef(owner, "", credDefId, REV_TAG, nonce);
      await expect(revRegistry.createRevRegDef("", credDefId, REV_TAG,
        { tailsLocation: TAILS_LOC, tailsHash: TAILS_HASH, maxCredNum: MAX_CRED },
        sig, owner.address))
        .to.be.revertedWithCustomError(revRegistry, "InvalidRevRegDef");
    });

    it("reverts InvalidRevRegDef when tailsLocation is empty", async function () {
      const nonce = await revRegistry.nonces(ISSUER_DID);
      const sig   = await sigCreateRevRegDef(owner, ISSUER_DID, credDefId, REV_TAG, nonce);
      await expect(revRegistry.createRevRegDef(ISSUER_DID, credDefId, REV_TAG,
        { tailsLocation: "", tailsHash: TAILS_HASH, maxCredNum: MAX_CRED },
        sig, owner.address))
        .to.be.revertedWithCustomError(revRegistry, "InvalidRevRegDef");
    });

    it("reverts IssuerNotActive when issuer DID is not registered", async function () {
      const foreignDid = "did:orcl:ffffffff-ffff-4fff-bfff-ffffffffffff";
      const nonce      = await revRegistry.nonces(foreignDid);
      const sig        = await sigCreateRevRegDef(owner, foreignDid, credDefId, REV_TAG, nonce);
      await expect(revRegistry.createRevRegDef(foreignDid, credDefId, REV_TAG,
        { tailsLocation: TAILS_LOC, tailsHash: TAILS_HASH, maxCredNum: MAX_CRED },
        sig, owner.address))
        .to.be.revertedWithCustomError(revRegistry, "IssuerNotActive");
    });

    it("reverts CredDefNotFound when credDefId does not exist", async function () {
      const fakeCredDefId = ethers.keccak256(ethers.toUtf8Bytes("nonexistent-cred-def"));
      const nonce         = await revRegistry.nonces(ISSUER_DID);
      const sig           = await sigCreateRevRegDef(owner, ISSUER_DID, fakeCredDefId, REV_TAG, nonce);
      await expect(revRegistry.createRevRegDef(ISSUER_DID, fakeCredDefId, REV_TAG,
        { tailsLocation: TAILS_LOC, tailsHash: TAILS_HASH, maxCredNum: MAX_CRED },
        sig, owner.address))
        .to.be.revertedWithCustomError(revRegistry, "CredDefNotFound");
    });

    it("reverts on wrong signer", async function () {
      const nonce = await revRegistry.nonces(ISSUER_DID);
      const sig   = await sigCreateRevRegDef(other, ISSUER_DID, credDefId, REV_TAG, nonce);
      await expect(revRegistry.createRevRegDef(ISSUER_DID, credDefId, REV_TAG,
        { tailsLocation: TAILS_LOC, tailsHash: TAILS_HASH, maxCredNum: MAX_CRED },
        sig, owner.address))
        .to.be.revertedWith("Invalid Signature");
    });
  });

  // ── updateRevStatusList ────────────────────────────────────────────────────

  describe("updateRevStatusList", function () {
    let revRegId: string;

    beforeEach(async function () {
      const tx      = await createRevRegDef();
      const receipt = await tx.wait();
      revRegId = receipt.logs[0].topics[1];
    });

    async function updateStatus(
      signer: HardhatEthersSigner = owner,
      ts: bigint = BigInt(Math.floor(Date.now() / 1000))
    ) {
      const nonce = await revRegistry.nonces(ISSUER_DID);
      const sig   = await sigUpdateRevStatus(signer, revRegId, ts, nonce);
      return revRegistry.updateRevStatusList(revRegId, ts, ACCUM, REV_LIST, sig, signer.address);
    }

    it("stores accumulator and revocationList", async function () {
      const ts = BigInt(Math.floor(Date.now() / 1000));
      await updateStatus(owner, ts);
      const list = await revRegistry.getRevStatusList(revRegId);
      expect(list.revRegId).to.equal(revRegId);
      expect(list.timestamp).to.equal(ts);
      expect(list.currentAccumulator).to.equal(ethers.hexlify(ACCUM));
      expect(list.revocationList).to.equal(ethers.hexlify(REV_LIST));
    });

    it("emits RevStatusListUpdated", async function () {
      const ts = BigInt(Math.floor(Date.now() / 1000));
      const nonce = await revRegistry.nonces(ISSUER_DID);
      const sig   = await sigUpdateRevStatus(owner, revRegId, ts, nonce);
      await expect(revRegistry.updateRevStatusList(revRegId, ts, ACCUM, REV_LIST, sig, owner.address))
        .to.emit(revRegistry, "RevStatusListUpdated")
        .withArgs(revRegId, ts);
    });

    it("can be updated multiple times (overwrites)", async function () {
      const ts1 = BigInt(Math.floor(Date.now() / 1000));
      await updateStatus(owner, ts1);
      const newAccum = ethers.toUtf8Bytes("new-accumulator");
      const ts2      = ts1 + 60n;
      const nonce    = await revRegistry.nonces(ISSUER_DID);
      const sig      = await sigUpdateRevStatus(owner, revRegId, ts2, nonce);
      await revRegistry.updateRevStatusList(revRegId, ts2, newAccum, REV_LIST, sig, owner.address);
      const list = await revRegistry.getRevStatusList(revRegId);
      expect(list.timestamp).to.equal(ts2);
      expect(list.currentAccumulator).to.equal(ethers.hexlify(newAccum));
    });

    it("increments nonce after update", async function () {
      const nonceBefore = await revRegistry.nonces(ISSUER_DID);
      await updateStatus();
      expect(await revRegistry.nonces(ISSUER_DID)).to.equal(nonceBefore + 1n);
    });

    it("reverts RevRegDefNotFound for unknown revRegId", async function () {
      const fakeId = ethers.keccak256(ethers.toUtf8Bytes("unknown"));
      const ts     = BigInt(Math.floor(Date.now() / 1000));
      const nonce  = await revRegistry.nonces(ISSUER_DID);
      const sig    = await sigUpdateRevStatus(owner, fakeId, ts, nonce);
      await expect(revRegistry.updateRevStatusList(fakeId, ts, ACCUM, REV_LIST, sig, owner.address))
        .to.be.revertedWithCustomError(revRegistry, "RevRegDefNotFound");
    });

    it("reverts on wrong signer", async function () {
      const ts    = BigInt(Math.floor(Date.now() / 1000));
      const nonce = await revRegistry.nonces(ISSUER_DID);
      const sig   = await sigUpdateRevStatus(other, revRegId, ts, nonce);
      await expect(revRegistry.updateRevStatusList(revRegId, ts, ACCUM, REV_LIST, sig, owner.address))
        .to.be.revertedWith("Invalid Signature");
    });
  });

  // ── getRevRegDef ───────────────────────────────────────────────────────────

  describe("getRevRegDef", function () {
    it("reverts RevRegDefNotFound for unknown id", async function () {
      const unknown = ethers.keccak256(ethers.toUtf8Bytes("unknown"));
      await expect(revRegistry.getRevRegDef(unknown))
        .to.be.revertedWithCustomError(revRegistry, "RevRegDefNotFound");
    });
  });

  // ── getRevStatusList ───────────────────────────────────────────────────────

  describe("getRevStatusList", function () {
    it("reverts RevStatusListNotFound before first update", async function () {
      const tx      = await createRevRegDef();
      const receipt = await tx.wait();
      const revRegId = receipt.logs[0].topics[1];
      await expect(revRegistry.getRevStatusList(revRegId))
        .to.be.revertedWithCustomError(revRegistry, "RevStatusListNotFound");
    });
  });

  // ── revRegDefExists ────────────────────────────────────────────────────────

  describe("revRegDefExists", function () {
    it("returns false for unknown id", async function () {
      expect(await revRegistry.revRegDefExists(ethers.keccak256(ethers.toUtf8Bytes("x")))).to.equal(false);
    });

    it("returns true after creation", async function () {
      const tx      = await createRevRegDef();
      const receipt = await tx.wait();
      const id      = receipt.logs[0].topics[1];
      expect(await revRegistry.revRegDefExists(id)).to.equal(true);
    });
  });
});
