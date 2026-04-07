/**
 * SchemaRegistry tests — written before implementation (TDD).
 *
 * Spec source: pkg/acr/schema.go
 *   - IssuerId: required non-empty
 *   - Name:     required non-empty
 *   - Version:  required non-empty
 *   - AttrNames: required, min 1 element
 *   - Key:      keccak256(abi.encode(issuerId, name, version))
 *
 * Authorization: issuerId must be an active DID in the registry.
 * Replay protection: nonce per issuerId, included in payload hash.
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

// ─── signing helpers ──────────────────────────────────────────────────────────

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
  };
}

async function sign(signer: HardhatEthersSigner, hash: string) {
  return signer.signMessage(ethers.getBytes(hash));
}

function h(types: string[], values: unknown[]) {
  return ethers.keccak256(ethers.solidityPacked(types, values));
}

async function sigCreateDid(signer: HardhatEthersSigner, did: string, nonce: bigint) {
  return sign(signer, h(["string", "uint256"], [did, nonce]));
}

async function sigPublishSchema(
  signer: HardhatEthersSigner,
  issuerId: string,
  name: string,
  version: string,
  nonce: bigint
) {
  return sign(signer, h(["string", "string", "string", "uint256"], [issuerId, name, version, nonce]));
}

// ─── suite ────────────────────────────────────────────────────────────────────

describe("SchemaRegistry", function () {
  let didRegistry: any;
  let schemaRegistry: any;
  let owner: HardhatEthersSigner;
  let other: HardhatEthersSigner;

  beforeEach(async function () {
    [owner, other] = await ethers.getSigners();

    // Deploy DID registry first — SchemaRegistry validates issuer DID state
    didRegistry = await (await ethers.getContractFactory("didController")).deploy();

    // Register the issuer DID so it is Active
    const nonce = await didRegistry.nonces(ISSUER_DID);
    await didRegistry.createDid(
      makeIssuerDoc(owner.address),
      await sigCreateDid(owner, ISSUER_DID, nonce),
      owner.address
    );

    // Deploy SchemaRegistry, passing didRegistry address
    schemaRegistry = await (
      await ethers.getContractFactory("SchemaRegistry")
    ).deploy(await didRegistry.getAddress());
  });

  // ── publishSchema ──────────────────────────────────────────────────────────

  describe("publishSchema", function () {
    async function publish(
      signer: HardhatEthersSigner = owner,
      issuerId = ISSUER_DID,
      name = SCHEMA_NAME,
      version = SCHEMA_VER,
      attrNames = ATTR_NAMES
    ) {
      const nonce = await schemaRegistry.nonces(issuerId);
      const sig   = await sigPublishSchema(signer, issuerId, name, version, nonce);
      return schemaRegistry.publishSchema(issuerId, name, version, attrNames, sig, signer.address);
    }

    it("returns a deterministic bytes32 id = keccak256(issuerId, name, version)", async function () {
      const expected = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["string", "string", "string"],
          [ISSUER_DID, SCHEMA_NAME, SCHEMA_VER]
        )
      );
      const nonce = await schemaRegistry.nonces(ISSUER_DID);
      const sig   = await sigPublishSchema(owner, ISSUER_DID, SCHEMA_NAME, SCHEMA_VER, nonce);
      const id    = await schemaRegistry.publishSchema.staticCall(ISSUER_DID, SCHEMA_NAME, SCHEMA_VER, ATTR_NAMES, sig, owner.address);
      expect(id).to.equal(expected);
    });

    it("stores all schema fields retrievable via getSchema", async function () {
      const tx = await publish();
      const receipt = await tx.wait();
      const id   = receipt.logs[0].topics[1]; // SchemaPublished first indexed arg
      const schema = await schemaRegistry.getSchema(id);
      expect(schema.issuerId).to.equal(ISSUER_DID);
      expect(schema.name).to.equal(SCHEMA_NAME);
      expect(schema.version).to.equal(SCHEMA_VER);
      expect(schema.attrNames).to.deep.equal(ATTR_NAMES);
    });

    it("emits SchemaPublished with correct args", async function () {
      const nonce = await schemaRegistry.nonces(ISSUER_DID);
      const sig   = await sigPublishSchema(owner, ISSUER_DID, SCHEMA_NAME, SCHEMA_VER, nonce);
      await expect(schemaRegistry.publishSchema(ISSUER_DID, SCHEMA_NAME, SCHEMA_VER, ATTR_NAMES, sig, owner.address))
        .to.emit(schemaRegistry, "SchemaPublished")
        .withArgs(anyValue, ISSUER_DID, SCHEMA_NAME, SCHEMA_VER);
    });

    it("increments nonce per issuerId after publish", async function () {
      await publish();
      expect(await schemaRegistry.nonces(ISSUER_DID)).to.equal(1n);
    });

    it("reverts SchemaAlreadyExists on duplicate (same issuerId + name + version)", async function () {
      await publish();
      await expect(publish()).to.be.revertedWithCustomError(schemaRegistry, "SchemaAlreadyExists");
    });

    it("reverts InvalidSchema when issuerId is empty", async function () {
      const nonce = await schemaRegistry.nonces("");
      const sig   = await sigPublishSchema(owner, "", SCHEMA_NAME, SCHEMA_VER, nonce);
      await expect(schemaRegistry.publishSchema("", SCHEMA_NAME, SCHEMA_VER, ATTR_NAMES, sig, owner.address))
        .to.be.revertedWithCustomError(schemaRegistry, "InvalidSchema");
    });

    it("reverts InvalidSchema when name is empty", async function () {
      const nonce = await schemaRegistry.nonces(ISSUER_DID);
      const sig   = await sigPublishSchema(owner, ISSUER_DID, "", SCHEMA_VER, nonce);
      await expect(schemaRegistry.publishSchema(ISSUER_DID, "", SCHEMA_VER, ATTR_NAMES, sig, owner.address))
        .to.be.revertedWithCustomError(schemaRegistry, "InvalidSchema");
    });

    it("reverts InvalidSchema when version is empty", async function () {
      const nonce = await schemaRegistry.nonces(ISSUER_DID);
      const sig   = await sigPublishSchema(owner, ISSUER_DID, SCHEMA_NAME, "", nonce);
      await expect(schemaRegistry.publishSchema(ISSUER_DID, SCHEMA_NAME, "", ATTR_NAMES, sig, owner.address))
        .to.be.revertedWithCustomError(schemaRegistry, "InvalidSchema");
    });

    it("reverts InvalidSchema when attrNames is empty", async function () {
      const nonce = await schemaRegistry.nonces(ISSUER_DID);
      const sig   = await sigPublishSchema(owner, ISSUER_DID, SCHEMA_NAME, SCHEMA_VER, nonce);
      await expect(schemaRegistry.publishSchema(ISSUER_DID, SCHEMA_NAME, SCHEMA_VER, [], sig, owner.address))
        .to.be.revertedWithCustomError(schemaRegistry, "InvalidSchema");
    });

    it("reverts IssuerNotActive when issuer DID is not registered", async function () {
      const foreignDid = "did:orcl:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
      const nonce      = await schemaRegistry.nonces(foreignDid);
      const sig        = await sigPublishSchema(owner, foreignDid, SCHEMA_NAME, SCHEMA_VER, nonce);
      await expect(schemaRegistry.publishSchema(foreignDid, SCHEMA_NAME, SCHEMA_VER, ATTR_NAMES, sig, owner.address))
        .to.be.revertedWithCustomError(schemaRegistry, "IssuerNotActive");
    });

    it("reverts on wrong signer", async function () {
      const nonce = await schemaRegistry.nonces(ISSUER_DID);
      const sig   = await sigPublishSchema(other, ISSUER_DID, SCHEMA_NAME, SCHEMA_VER, nonce);
      await expect(schemaRegistry.publishSchema(ISSUER_DID, SCHEMA_NAME, SCHEMA_VER, ATTR_NAMES, sig, owner.address))
        .to.be.revertedWith("Invalid Signature");
    });
  });

  // ── getSchema ──────────────────────────────────────────────────────────────

  describe("getSchema", function () {
    it("reverts SchemaNotFound for an unknown id", async function () {
      const unknownId = ethers.keccak256(ethers.toUtf8Bytes("nonexistent"));
      await expect(schemaRegistry.getSchema(unknownId))
        .to.be.revertedWithCustomError(schemaRegistry, "SchemaNotFound");
    });
  });

  // ── schemaExists ───────────────────────────────────────────────────────────

  describe("schemaExists", function () {
    it("returns false for unknown id", async function () {
      expect(await schemaRegistry.schemaExists(ethers.keccak256(ethers.toUtf8Bytes("x")))).to.equal(false);
    });

    it("returns true after publish", async function () {
      const nonce = await schemaRegistry.nonces(ISSUER_DID);
      const sig   = await sigPublishSchema(owner, ISSUER_DID, SCHEMA_NAME, SCHEMA_VER, nonce);
      await schemaRegistry.publishSchema(ISSUER_DID, SCHEMA_NAME, SCHEMA_VER, ATTR_NAMES, sig, owner.address);
      const id    = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(["string","string","string"], [ISSUER_DID, SCHEMA_NAME, SCHEMA_VER])
      );
      expect(await schemaRegistry.schemaExists(id)).to.equal(true);
    });
  });
});
