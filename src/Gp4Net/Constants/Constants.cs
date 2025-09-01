// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants;

/// <summary>
/// Unified constants system for the Gp4Net codebase following the same architectural pattern
/// as UnifiedCryptoService. Replaces all scattered magic number literals with organized,
/// well-documented constant definitions grouped by functional domain.
///
/// Organization Strategy:
/// - Each protocol/standard gets its own partial class (e.g., UnifiedConstants.GlobalPlatform.cs)
/// - Constants are grouped into nested static classes for logical organization
/// - All hex values use Convert.FromHexString() for clarity and type safety
/// - Comprehensive XML documentation with specification references
/// - Immutable arrays for byte sequences (readonly for reference types)
///
/// Design Principles:
/// - Single source of truth for all magic numbers in the codebase
/// - Functional organization by protocol/domain rather than by type
/// - Zero duplication - every constant appears exactly once
/// - Specification-driven naming and documentation
/// - Easy discoverability through IntelliSense
///
/// Usage Pattern:
/// - Replace hardcoded 0x80 with UnifiedConstants.GlobalPlatform.Cla.Standard
/// - Replace hardcoded "A000000003000000" with UnifiedConstants.GlobalPlatform.Aids.IsdDefault
/// - Replace hardcoded 16 with UnifiedConstants.GlobalPlatform.Crypto.AesKeySize
///
/// This eliminates the need to memorize or lookup magic numbers and ensures consistency
/// across the entire codebase while maintaining perfect functional programming principles.
/// </summary>
[PublicAPI]
public static partial class Constants
{
    // Base partial class - contains no constants itself
    // All actual constants are defined in domain-specific partial classes
    // This provides the unified entry point: UnifiedConstants.GlobalPlatform.Cla.Standard
}
