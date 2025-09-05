// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using JetBrains.Annotations;

namespace Gp4Net.Constants;

/// <summary>
/// Unified constants system for the Gp4Net codebase.
///
/// Organization Strategy:
/// - Each protocol/standard gets its own partial class (e.g., UnifiedConstants.GlobalPlatform.cs)
/// - Constants are grouped into nested static classes for logical organization
/// - Comprehensive XML documentation with specification references
/// - Immutable arrays for byte sequences (readonly for reference types)
///
/// Design Principles:
/// - Single source of truth for all magic numbers in the codebase
/// - Functional organization by protocol/domain rather than by type
/// - Avoid duplication - every constant appears exactly once
/// - Specification-driven naming and documentation
/// - Easy discoverability through IntelliSense
/// </summary>
[PublicAPI]
public static partial class Constants
{
    /// <summary>
    /// Common bit masks used throughout the codebase.
    /// </summary>
    public static class BitMasks
    {
        /// <summary>Lower byte mask (0xFF).</summary>
        public const byte LowerByte = 0xFF;
    }
}
