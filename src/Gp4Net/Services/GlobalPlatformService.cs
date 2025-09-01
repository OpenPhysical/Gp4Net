// -----------------------------------------------------------------------------
// Copyright (c) 2025 Mistial Developer <opensource@mistial.dev>
// SPDX-License-Identifier: AGPL-3.0-only
// -----------------------------------------------------------------------------

using CSharpFunctionalExtensions;
using JetBrains.Annotations;

namespace Gp4Net.Services;

/// <summary>
/// Unified GlobalPlatform service consolidating ALL GlobalPlatform operations in the Gp4Net codebase.
/// Replaces scattered modules and services with a single, comprehensive, functionally pure service.
/// Organized by operation type with nested static classes for logical grouping.
/// All methods are static, pure functional, and return Result&lt;T, SmartCardError&gt;.
/// 
/// Organization Strategy:
/// - Each functional domain gets its own partial class file
/// - Operations are grouped into nested static classes for logical organization  
/// - All methods are static and pure functional
/// - Dependencies passed as functional parameters (no DI)
/// - Comprehensive XML documentation with GP specification references
/// 
/// Design Principles:
/// - Single source of truth for all GlobalPlatform operations
/// - Functional organization by operation type rather than by protocol layer
/// - Zero duplication - every operation appears exactly once
/// - Specification-driven implementation with references
/// - Easy discoverability through IntelliSense
/// 
/// Usage Pattern:
/// - GlobalPlatformService.Discovery.DetectAndSelectIsdAsync(...)
/// - GlobalPlatformService.SecureChannel.EstablishAsync(...)
/// - GlobalPlatformService.Applications.InstallAsync(...)
/// 
/// This eliminates the need for multiple service instances and ensures consistency
/// across the entire codebase while maintaining perfect functional programming principles.
/// </summary>
[PublicAPI]
public static partial class GlobalPlatformService
{
    // Base partial class - contains no operations itself
    // All actual operations are defined in domain-specific partial classes
    // This provides the unified entry point for all GlobalPlatform operations
}