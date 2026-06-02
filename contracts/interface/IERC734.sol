// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.27;

/**
 * @dev Interface of the ERC734 (Key Holder) standard as defined in the EIP, registry-only.
 *
 * @notice The original `execute(address,uint256,bytes)` and `approve(uint256,bool)` selectors
 *         live in the {KeyApprovalModule} (an ERC-7579 fallback handler + executor). They are
 *         still reachable on every Identity at the standard ERC-734 selectors via the account's
 *         fallback, but they live behind a separate Solidity type — {IKeyExecutor} — to keep
 *         the registry interface decoupled from the execution surface.
 *
 *         See {IKeyExecutor} for the queue ABI, and {KeyApprovalModule} for the implementation.
 */
interface IERC734 {

    /**
     * @dev Emitted when an execution request was approved. Lives on {IKeyExecutor} in practice
     *      (the queue module emits it); declared here for the legacy ERC-734 ABI surface.
     */
    event Approved(uint256 indexed executionId, bool approved);

    /// @dev Emitted when an approved execution successfully runs through the queue.
    event Executed(uint256 indexed executionId, address indexed to, uint256 indexed value, bytes data);

    /// @dev Emitted when an execution is queued.
    event ExecutionRequested(uint256 indexed executionId, address indexed to, uint256 indexed value, bytes data);

    /// @dev Emitted when an approved execution fails inside the queue.
    event ExecutionFailed(uint256 indexed executionId, address indexed to, uint256 indexed value, bytes data);

    /// @dev Emitted when a key is added to the identity. MUST be triggered when addKey succeeds.
    event KeyAdded(bytes32 indexed key, uint256 indexed purpose, uint256 indexed keyType);

    /// @dev Emitted when a purpose is removed from a key.
    event KeyRemoved(bytes32 indexed key, uint256 indexed purpose, uint256 indexed keyType);

    /**
     * @dev Adds a _key to the identity. MUST only be done by keys of purpose MANAGEMENT,
     * or the identity itself.
     */
    function addKey(bytes32 _key, uint256 _purpose, uint256 _keyType) external returns (bool success);

    /**
     * @dev Removes _purpose for _key from the identity. MUST only be done by keys of purpose
     * MANAGEMENT, or the identity itself.
     */
    function removeKey(bytes32 _key, uint256 _purpose) external returns (bool success);

    /// @dev Returns the full key data, if present.
    function getKey(bytes32 _key) external view returns (uint256[] memory purposes, uint256 keyType, bytes32 key);

    /// @dev Returns the purposes for a key.
    function getKeyPurposes(bytes32 _key) external view returns (uint256[] memory _purposes);

    /// @dev Returns the key hashes registered with a given purpose.
    function getKeysByPurpose(uint256 _purpose) external view returns (bytes32[] memory keys);

    /// @dev Returns TRUE if a key has the given purpose, or MANAGEMENT (universal).
    function keyHasPurpose(bytes32 _key, uint256 _purpose) external view returns (bool exists);

}
