// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Equivalent to service.go
struct Service {
    string id;
    string serviceType; // 'type' is a reserved keyword, using 'serviceType'
    string serviceEndpoint;
}

/// @notice Sub-component of document.go
struct VerificationMethod {
    string id;
    string controller;
    string keyType;
    bytes publicKeyMultibase;
}

/// @notice Equivalent to document.go
struct DidDocument {
    string id;
    string[] controller;
    VerificationMethod[] verificationMethods;
    string[] authentication;
    Service[] services;
}

/// @notice Equivalent to metadata.go
struct DocumentMetadata {
    uint256 created;     // Stored as block.timestamp
    uint256 updated;     // Stored as block.timestamp
    bool deactivated;
    string versionId;
}

/// @notice Equivalent to state.go
enum DidState { Unregistered, Active, Deactivated }

/// @notice Equivalent to record.go (The top-level storage object)
struct DidRecord {
    DidDocument document;
    DocumentMetadata metadata;
    DidState state;
}