/**
 * CredDefRegistry tests — written before implementation (TDD).
 *
 * Spec source: pkg/acr/credentialDefinition.go
 *   - IssuerId:  required non-empty  (L82)
 *   - SchemaId:  required non-empty, must exist in SchemaRegistry (L85)
 *   - Type:      CredDefType enum — only CL supported (default:"CL")
 *   - Tag:       no validation in chaincode
 *   - Value:     CL public key material — arbitrary bytes
 *   - Key:       keccak256(abi.encode(issuerId, schemaId, tag))
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
const CD_TAG      = "default";
const CD_VALUE    = ethers.toUtf8Bytes(JSON.stringify({ n: "abc123", s: "def456", rms: {}, r: {}, rctxt: "ghi", z: "jkl" }));
const CL          = 0; // CredDefType.CL

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

async function sigPublishSchema(signer: HardhatEthersSigner, issuerId: string, name: string, version: string, nonce: bigint) {
  return sign(signer, h(["string", "string", "string", "uint256"], [issuerId, name, version, nonce]));
}

async function sigPublishCredDef(
  signer: HardhatEthersSigner,
  issuerId: string,
  schemaId: string, // bytes32 hex string
  tag: string,
  nonce: bigint
) {
  return sign(signer, h(["string", "bytes32", "string", "uint256"], [issuerId, schemaId, tag, nonce]));
}

// ─── suite ────────────────────────────────────────────────────────────────────

describe("CredDefRegistry", function () {
  let didRegistry: any;
  let schemaRegistry: any;
  let credDefRegistry: any;
  let owner: HardhatEthersSigner;
  let other: HardhatEthersSigner;
  let schemaId: string; // bytes32

  beforeEach(async function () {
    [owner, other] = await ethers.getSigners();

    // Deploy dependency chain
    didRegistry    = await (await ethers.getContractFactory("didController")).deploy();
    schemaRegistry = await (await ethers.getContractFactory("SchemaRegistry")).deploy(await didRegistry.getAddress());
    credDefRegistry = await (await ethers.getContractFactory("CredDefRegistry")).deploy(
      await didRegistry.getAddress(),
      await schemaRegistry.getAddress()
    );

    // Register issuer DID
    const didNonce = await didRegistry.nonces(ISSUER_DID);
    await didRegistry.createDid(makeIssuerDoc(owner.address), await sigCreateDid(owner, ISSUER_DID, didNonce), owner.address);

    // Publish a schema to reference in cred def tests
    const schemaNonce = await schemaRegistry.nonces(ISSUER_DID);
    const schemaSig   = await sigPublishSchema(owner, ISSUER_DID, SCHEMA_NAME, SCHEMA_VER, schemaNonce);
    const tx          = await schemaRegistry.publishSchema(ISSUER_DID, SCHEMA_NAME, SCHEMA_VER, ATTR_NAMES, schemaSig, owner.address);
    const receipt     = await tx.wait();
    schemaId = receipt.logs[0].topics[1]; // bytes32 from SchemaPublished event
  });

  // ── publishCredDef ─────────────────────────────────────────────────────────

  describe("publishCredDef", function () {
    async function publish(
      signer: HardhatEthersSigner = owner,
      issuerId = ISSUER_DID,
      sid = schemaId,
      tag = CD_TAG,
      value = CD_VALUE
    ) {
      const nonce = await credDefRegistry.nonces(issuerId);
      const sig   = await sigPublishCredDef(signer, issuerId, sid, tag, nonce);
      return credDefRegistry.publishCredDef(issuerId, sid, CL, tag, value, sig, signer.address);
    }

    it("returns a deterministic bytes32 id = keccak256(issuerId, schemaId, tag)", async function () {
      const expected = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ["string", "bytes32", "string"],
          [ISSUER_DID, schemaId, CD_TAG]
        )
      );
      const nonce = await credDefRegistry.nonces(ISSUER_DID);
      const sig   = await sigPublishCredDef(owner, ISSUER_DID, schemaId, CD_TAG, nonce);
      const id    = await credDefRegistry.publishCredDef.staticCall(ISSUER_DID, schemaId, CL, CD_TAG, CD_VALUE, sig, owner.address);
      expect(id).to.equal(expected);
    });

    it("stores all fields retrievable via getCredDef", async function () {
      const tx      = await publish();
      const receipt = await tx.wait();
      const id      = receipt.logs[0].topics[1];
      const cd      = await credDefRegistry.getCredDef(id);
      expect(cd.issuerId).to.equal(ISSUER_DID);
      expect(cd.schemaId).to.equal(schemaId);
      expect(cd.credDefType).to.equal(CL);
      expect(cd.tag).to.equal(CD_TAG);
      expect(cd.value).to.equal(ethers.hexlify(CD_VALUE));
    });

    it("emits CredDefPublished with correct args", async function () {
      const nonce = await credDefRegistry.nonces(ISSUER_DID);
      const sig   = await sigPublishCredDef(owner, ISSUER_DID, schemaId, CD_TAG, nonce);
      await expect(credDefRegistry.publishCredDef(ISSUER_DID, schemaId, CL, CD_TAG, CD_VALUE, sig, owner.address))
        .to.emit(credDefRegistry, "CredDefPublished")
        .withArgs(anyValue, ISSUER_DID, schemaId, CD_TAG);
    });

    it("increments nonce per issuerId after publish", async function () {
      await publish();
      expect(await credDefRegistry.nonces(ISSUER_DID)).to.equal(1n);
    });

    it("allows multiple CredDefs per schema with different tags", async function () {
      await publish(owner, ISSUER_DID, schemaId, "tag-a");
      await publish(owner, ISSUER_DID, schemaId, "tag-b");
      // Both should succeed — different keys
    });

    it("reverts CredDefAlreadyExists on exact duplicate (same issuerId + schemaId + tag)", async function () {
      await publish();
      await expect(publish()).to.be.revertedWithCustomError(credDefRegistry, "CredDefAlreadyExists");
    });

    // NOTE: A true keccak256 pre-image collision (different inputs → same hash) is
    // computationally infeasible to construct in a test environment.  The KeyCollision
    // error path is verified via code review and is exercised by a Foundry invariant
    // fuzzer in a separate hardening suite.  The pre-image comparison logic ensures
    // that if two different (issuerId, schemaId, tag) tuples ever produce the same
    // keccak256 digest, the contract reverts KeyCollision rather than silently
    // overwriting or emitting a misleading CredDefAlreadyExists.
    it("KeyCollision error exists on the contract ABI", async function () {
      const iface = credDefRegistry.interface;
      expect(iface.getError("KeyCollision")).to.not.be.undefined;
    });

    it("reverts InvalidCredDef when issuerId is empty", async function () {
      const nonce = await credDefRegistry.nonces("");
      const sig   = await sigPublishCredDef(owner, "", schemaId, CD_TAG, nonce);
      await expect(credDefRegistry.publishCredDef("", schemaId, CL, CD_TAG, CD_VALUE, sig, owner.address))
        .to.be.revertedWithCustomError(credDefRegistry, "InvalidCredDef");
    });

    it("reverts SchemaNotFound when schemaId does not exist in SchemaRegistry", async function () {
      const fakeSchemaId = ethers.keccak256(ethers.toUtf8Bytes("nonexistent-schema"));
      const nonce        = await credDefRegistry.nonces(ISSUER_DID);
      const sig          = await sigPublishCredDef(owner, ISSUER_DID, fakeSchemaId, CD_TAG, nonce);
      await expect(credDefRegistry.publishCredDef(ISSUER_DID, fakeSchemaId, CL, CD_TAG, CD_VALUE, sig, owner.address))
        .to.be.revertedWithCustomError(credDefRegistry, "SchemaNotFound");
    });

    it("reverts IssuerNotActive when issuer DID is not registered", async function () {
      const foreignDid = "did:orcl:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
      const nonce      = await credDefRegistry.nonces(foreignDid);
      const sig        = await sigPublishCredDef(owner, foreignDid, schemaId, CD_TAG, nonce);
      await expect(credDefRegistry.publishCredDef(foreignDid, schemaId, CL, CD_TAG, CD_VALUE, sig, owner.address))
        .to.be.revertedWithCustomError(credDefRegistry, "IssuerNotActive");
    });

    it("reverts on wrong signer", async function () {
      const nonce = await credDefRegistry.nonces(ISSUER_DID);
      const sig   = await sigPublishCredDef(other, ISSUER_DID, schemaId, CD_TAG, nonce);
      await expect(credDefRegistry.publishCredDef(ISSUER_DID, schemaId, CL, CD_TAG, CD_VALUE, sig, owner.address))
        .to.be.revertedWith("Invalid Signature");
    });
  });

  // ── getCredDef ─────────────────────────────────────────────────────────────

  describe("getCredDef", function () {
    it("reverts CredDefNotFound for an unknown id", async function () {
      const unknownId = ethers.keccak256(ethers.toUtf8Bytes("nonexistent"));
      await expect(credDefRegistry.getCredDef(unknownId))
        .to.be.revertedWithCustomError(credDefRegistry, "CredDefNotFound");
    });
  });
});
