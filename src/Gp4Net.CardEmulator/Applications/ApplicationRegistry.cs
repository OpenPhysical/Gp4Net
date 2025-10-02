using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;
using CSharpFunctionalExtensions;
using Gp4Net.CardEmulator.Functional;
using Gp4Net.Core;
using Gp4Net.Cryptography;
using Gp4Net.Shared;
using JetBrains.Annotations;
using static Gp4Net.Constants.Constants.GlobalPlatform;
using static Gp4Net.Services.TlvService;
using ApduIns = Gp4Net.Constants.Apdu.Instructions;
using GpIns = Gp4Net.Constants.Constants.GlobalPlatform.Ins;

namespace Gp4Net.CardEmulator.Applications;

/// <summary>
/// Manages application registry and APDU routing per GP Card Specification.
/// Maintains functional programming principles with immutable state.
/// Reference: GP Card Specification v2.3.1 Section 6.4 (Application Management)
/// </summary>
[PublicAPI]
public sealed record ApplicationRegistry
{
    public ImmutableDictionary<ImmutableArray<byte>, IApplication> Applications { get; init; }
    public Maybe<ImmutableArray<byte>> SelectedApplicationAid { get; init; }

    private ApplicationRegistry(
        ImmutableDictionary<ImmutableArray<byte>, IApplication> applications,
        Maybe<ImmutableArray<byte>> selectedApplicationAid
    )
    {
        Applications = applications;
        SelectedApplicationAid = selectedApplicationAid;
    }

    /// <summary>
    /// Creates registry with ISD as default selected application.
    /// Reference: GP Card Specification v2.3.1 Section 6.4.1 (ISD is implicitly selectable)
    /// </summary>
    public static Result<ApplicationRegistry, SmartCardError> CreateWithIsd(
        ImmutableArray<byte> isdAid,
        byte scpVersion = 0x02,
        byte scpImplementation = 0x15
    )
    {
        return IssuerSecurityDomain
            .Create(isdAid, scpVersion, scpImplementation)
            .Map(isd =>
            {
                var builder = ImmutableDictionary.CreateBuilder<ImmutableArray<byte>, IApplication>(
                    new AidEqualityComparer()
                );
                builder.Add(isdAid, isd);
                var applicationsWithIsd = builder.ToImmutable();

                return new ApplicationRegistry(
                    applications: applicationsWithIsd,
                    selectedApplicationAid: Maybe<ImmutableArray<byte>>.From(isdAid)
                );
            });
    }

    /// <summary>
    /// Creates registry with ISD including specific data objects from card configuration.
    /// Reference: GP Card Specification v2.3.1 Section 6.4.1 (ISD is implicitly selectable)
    /// </summary>
    public static Result<ApplicationRegistry, SmartCardError> CreateWithIsdAndDataObjects(
        ImmutableArray<byte> isdAid,
        ImmutableDictionary<ushort, byte[]> dataObjects,
        byte scpVersion = 0x02,
        byte scpImplementation = 0x15
    )
    {
        return IssuerSecurityDomain
            .CreateWithDataObjects(isdAid, dataObjects, scpVersion, scpImplementation)
            .Map(isd =>
            {
                var builder = ImmutableDictionary.CreateBuilder<ImmutableArray<byte>, IApplication>(
                    new AidEqualityComparer()
                );
                builder.Add(isdAid, isd);
                var applicationsWithIsd = builder.ToImmutable();

                return new ApplicationRegistry(
                    applications: applicationsWithIsd,
                    selectedApplicationAid: Maybe<ImmutableArray<byte>>.From(isdAid)
                );
            });
    }

    /// <summary>
    /// Routes APDU command to appropriate application based on current selection.
    /// Handles SELECT command specially as it affects application selection.
    /// Reference: GP Card Specification v2.3.1 Section 11.1 (SELECT command processing)
    /// </summary>
    public Result<
        (ApplicationRegistry UpdatedRegistry, ApduResponse Response, CardState UpdatedState),
        SmartCardError
    > RouteCommand(
        byte[] command,
        CardState cardState,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        if (command.Length < 4)
        {
            return Result.Success<(ApplicationRegistry, ApduResponse, CardState), SmartCardError>(
                (this, ApduResponse.WrongLength(), cardState)
            );
        }

        byte instruction = command[1];

        // Handle SELECT command specially - it affects application selection
        if (instruction == ApduIns.SELECT)
        {
            return ProcessSelectCommand(command, cardState)
                .Map(result =>
                {
                    var (updatedRegistry, response) = result;
                    var updatedState = cardState.WithApplicationRegistry(updatedRegistry);
                    return (updatedRegistry, response, updatedState);
                });
        }

        // Route to currently selected application
        return SelectedApplicationAid.Match(
            selectedAid => RouteToApplication(selectedAid, command, cardState, config, rngContext),
            () =>
                Result.Success<(ApplicationRegistry, ApduResponse, CardState), SmartCardError>(
                    (this, ApduResponse.ConditionsNotSatisfied(), cardState)
                )
        );
    }

    /// <summary>
    /// Adds a new application to the registry.
    /// </summary>
    public Result<ApplicationRegistry, SmartCardError> AddApplication(IApplication application)
    {
        if (Applications.ContainsKey(application.Aid))
        {
            return Result.Failure<ApplicationRegistry, SmartCardError>(
                ErrorFactory.ApplicationInstallationFailed("Application AID already exists")
            );
        }

        var builder = Applications.ToBuilder();
        builder.Add(application.Aid, application);
        var newApplications = builder.ToImmutable();

        return Result.Success<ApplicationRegistry, SmartCardError>(
            this with
            {
                Applications = newApplications,
            }
        );
    }

    /// <summary>
    /// Removes an application from the registry.
    /// </summary>
    public Result<ApplicationRegistry, SmartCardError> RemoveApplication(ImmutableArray<byte> aid)
    {
        if (!Applications.ContainsKey(aid))
        {
            return Result.Failure<ApplicationRegistry, SmartCardError>(
                ErrorFactory.ApplicationNotFound(Convert.ToHexString(aid.ToArray()))
            );
        }

        // If removing currently selected application, select ISD
        var updatedSelection = SelectedApplicationAid.Match(
            selectedAid =>
                selectedAid.SequenceEqual(aid)
                    ? GetIsdAid()
                    : Maybe<ImmutableArray<byte>>.From(selectedAid),
            () => Maybe<ImmutableArray<byte>>.None
        );

        var builder = Applications.ToBuilder();
        builder.Remove(aid);
        var newApplications = builder.ToImmutable();

        return Result.Success<ApplicationRegistry, SmartCardError>(
            this with
            {
                Applications = newApplications,
                SelectedApplicationAid = updatedSelection,
            }
        );
    }

    /// <summary>
    /// Updates an existing application in the registry.
    /// </summary>
    public Result<ApplicationRegistry, SmartCardError> UpdateApplication(
        IApplication updatedApplication
    )
    {
        if (!Applications.ContainsKey(updatedApplication.Aid))
        {
            return Result.Failure<ApplicationRegistry, SmartCardError>(
                ErrorFactory.ApplicationNotFound(
                    Convert.ToHexString(updatedApplication.Aid.ToArray())
                )
            );
        }

        var builder = Applications.ToBuilder();
        builder[updatedApplication.Aid] = updatedApplication;
        var newApplications = builder.ToImmutable();

        return Result.Success<ApplicationRegistry, SmartCardError>(
            this with
            {
                Applications = newApplications,
            }
        );
    }

    /// <summary>
    /// Gets all applications for GET STATUS command response.
    /// </summary>
    public ImmutableList<IApplication> GetAllApplications()
    {
        return Applications.Values.ToImmutableList();
    }

    /// <summary>
    /// Gets applications filtered by lifecycle state.
    /// </summary>
    public ImmutableList<IApplication> GetApplicationsByLifecycleState(LifecycleState state)
    {
        return Applications.Values.Where(app => app.LifecycleState == state).ToImmutableList();
    }

    #region Private Methods

    private Result<(ApplicationRegistry, ApduResponse), SmartCardError> ProcessSelectCommand(
        byte[] command,
        CardState cardState
    )
    {
        // Parse SELECT command per GP Card Specification Section 11.1
        if (command.Length < 4)
        {
            return Result.Success<(ApplicationRegistry, ApduResponse), SmartCardError>(
                (this, ApduResponse.WrongLength())
            );
        }

        byte p1 = command[2]; // ApduIns.Selection control
        byte p2 = command[3]; // File control info

        // For empty AID (Lc=0), select ISD
        if (command.Length == 4 || (command.Length == 5 && command[4] == 0))
        {
            return SelectIsd(p2);
        }

        // Extract AID from command
        if (command.Length < 6)
        {
            return Result.Success<(ApplicationRegistry, ApduResponse), SmartCardError>(
                (this, ApduResponse.WrongLength())
            );
        }

        byte lc = command[4];
        if (command.Length < 5 + lc)
        {
            return Result.Success<(ApplicationRegistry, ApduResponse), SmartCardError>(
                (this, ApduResponse.WrongLength())
            );
        }

        var targetAid = command[5..(5 + lc)].ToImmutableArray();

        return SelectApplication(targetAid, p1, p2);
    }

    private Result<(ApplicationRegistry, ApduResponse), SmartCardError> SelectIsd(
        byte fileControlInfo
    )
    {
        var isdAid = GetIsdAid();

        return isdAid.Match(
            aid =>
                Applications.TryGetValue(aid, out var isd)
                    ? SelectApplicationInternal(aid, isd, fileControlInfo)
                    : Result.Success<(ApplicationRegistry, ApduResponse), SmartCardError>(
                        (
                            this,
                            ApduResponse.Error(Constants.Constants.StatusWords.Legacy.FileNotFound)
                        )
                    ),
            () =>
                Result.Success<(ApplicationRegistry, ApduResponse), SmartCardError>(
                    (this, ApduResponse.Error(Constants.Constants.StatusWords.Legacy.FileNotFound))
                )
        );
    }

    private Result<(ApplicationRegistry, ApduResponse), SmartCardError> SelectApplication(
        ImmutableArray<byte> targetAid,
        byte selectionControl,
        byte fileControlInfo
    )
    {
        // Find application by exact or partial AID match
        return Applications.TryGetValue(targetAid, out var application)
            ? SelectApplicationInternal(targetAid, application, fileControlInfo)
            : TryPartialAidMatch(targetAid, selectionControl, fileControlInfo);
    }

    private Result<(ApplicationRegistry, ApduResponse), SmartCardError> TryPartialAidMatch(
        ImmutableArray<byte> targetAid,
        byte selectionControl,
        byte fileControlInfo
    )
    {
        // Find applications with AID that starts with targetAid (partial match)
        var matchingApps = Applications
            .Values.Where(app => app.Aid.Take(targetAid.Length).SequenceEqual(targetAid))
            .ToImmutableList();

        return matchingApps.Count switch
        {
            0
                => Result.Success<(ApplicationRegistry, ApduResponse), SmartCardError>(
                    (this, ApduResponse.Error(Constants.Constants.StatusWords.Legacy.FileNotFound))
                ),
            1 => SelectApplicationInternal(matchingApps[0].Aid, matchingApps[0], fileControlInfo),
            _
                => Result.Success<(ApplicationRegistry, ApduResponse), SmartCardError>(
                    (this, ApduResponse.Error(Constants.Constants.StatusWords.Legacy.FileNotFound))
                ), // Multiple matches - ambiguous
        };
    }

    private Result<(ApplicationRegistry, ApduResponse), SmartCardError> SelectApplicationInternal(
        ImmutableArray<byte> aid,
        IApplication application,
        byte fileControlInfo
    )
    {
        // Validate application can be selected
        return ValidateApplicationSelectable(application)
            .Map(app =>
            {
                var updatedRegistry = this with
                {
                    SelectedApplicationAid = Maybe<ImmutableArray<byte>>.From(aid),
                };
                var response = BuildSelectResponse(app, fileControlInfo);
                return (updatedRegistry, response);
            });
    }

    private Result<IApplication, SmartCardError> ValidateApplicationSelectable(
        IApplication application
    )
    {
        return application.LifecycleState switch
        {
            LifecycleState.Selectable => Result.Success<IApplication, SmartCardError>(application),
            LifecycleState.Personalized
                => Result.Success<IApplication, SmartCardError>(application),
            LifecycleState.Locked => Result.Success<IApplication, SmartCardError>(application), // Can still select but with limited functionality
            _
                => Result.Failure<IApplication, SmartCardError>(
                    SmartCardError.ConditionsNotSatisfied()
                ),
        };
    }

    private static ApduResponse BuildSelectResponse(IApplication application, byte fileControlInfo)
    {
        // Build FCI (File Control Information) response per GP specification
        return fileControlInfo switch
        {
            0x00 => BuildFciResponse(application), // Return FCI
            0x04 => BuildFcpResponse(application), // Return FCP
            0x08 => BuildFmdResponse(application), // Return FMD
            0x0C => ApduResponse.Success(), // No response data
            _ => ApduResponse.Success(), // Default to success with no data
        };
    }

    private static ApduResponse BuildFciResponse(IApplication application)
    {
        // Build FCI Template (Tag 6F) per ISO 7816-4
        var fciData = BuildFciTemplate(application);
        return ApduResponse.Success(fciData);
    }

    private static ApduResponse BuildFcpResponse(IApplication application)
    {
        // Build FCP Template (Tag 62)
        var fcpData = new byte[] { 0x62, 0x00 }; // Empty FCP template
        return ApduResponse.Success(fcpData);
    }

    private static ApduResponse BuildFmdResponse(IApplication application)
    {
        // Build FMD Template (Tag 64)
        var fmdData = new byte[] { 0x64, 0x00 }; // Empty FMD template
        return ApduResponse.Success(fmdData);
    }

    private static byte[] BuildFciTemplate(IApplication application)
    {
        // Build FCI Template per ISO 7816-4 and GP Card Specification
        // 6F [length]
        //   84 [aid_length] [aid]
        //   A5 [length]
        //     73 [length]
        //       06 [length] [object_identifier]
        //       60 [length]
        //         [application_specific_data]

        var aid = application.Aid;

        // Build AID TLV using service
        var aidTlvResult = TlvEncoder.EncodeSimple(0x84, aid);

        // Build FCI template with AID TLV using service
        var fciTemplateResult = aidTlvResult.Bind(aidTlv => TlvEncoder.EncodeSimple(0x6F, aidTlv));

        var fciTemplate = fciTemplateResult.Match(
            success => success.ToArray(),
            error => // Fallback to manual construction on service error
            {
                var aidArray = aid.ToArray();
                var aidTlvFallback = new byte[2 + aidArray.Length];
                aidTlvFallback[0] = 0x84;
                aidTlvFallback[1] = (byte)aidArray.Length;
                Array.Copy(aidArray, 0, aidTlvFallback, 2, aidArray.Length);

                var fciTemplateFallback = new byte[2 + aidTlvFallback.Length];
                fciTemplateFallback[0] = 0x6F;
                fciTemplateFallback[1] = (byte)aidTlvFallback.Length;
                Array.Copy(aidTlvFallback, 0, fciTemplateFallback, 2, aidTlvFallback.Length);
                return fciTemplateFallback;
            }
        );

        return fciTemplate;
    }

    private Result<
        (ApplicationRegistry UpdatedRegistry, ApduResponse Response, CardState UpdatedState),
        SmartCardError
    > RouteToApplication(
        ImmutableArray<byte> applicationAid,
        byte[] command,
        CardState cardState,
        CardConfiguration config,
        IRngContext rngContext
    )
    {
        return Applications.TryGetValue(applicationAid, out var application)
            ? ValidateApplicationState(application, command)
                .Bind(app => ValidateSecurityRequirements(app, command, cardState))
                .Bind(app => app.ProcessCommand(command, cardState, config, rngContext))
                .Map(result =>
                {
                    var (updatedApp, updatedState, response) = result;
                    var builder = Applications.ToBuilder();
                    builder[applicationAid] = updatedApp;
                    var newApplications = builder.ToImmutable();
                    var updatedRegistry = this with { Applications = newApplications };
                    var stateWithRegistry = updatedState.WithApplicationRegistry(updatedRegistry);
                    return (updatedRegistry, response, stateWithRegistry);
                })
            : Result.Success<(ApplicationRegistry, ApduResponse, CardState), SmartCardError>(
                (
                    this,
                    ApduResponse.Error(Constants.Constants.StatusWords.Legacy.FileNotFound),
                    cardState
                )
            );
    }

    private Result<IApplication, SmartCardError> ValidateApplicationState(
        IApplication app,
        byte[] command
    )
    {
        byte instruction = command[1];

        // Validate application lifecycle allows command processing
        return app.LifecycleState switch
        {
            LifecycleState.Selectable => Result.Success<IApplication, SmartCardError>(app),
            LifecycleState.Personalized => Result.Success<IApplication, SmartCardError>(app),
            LifecycleState.Locked
                => instruction == ApduIns.SELECT
                    ? Result.Success<IApplication, SmartCardError>(app)
                    : Result.Failure<IApplication, SmartCardError>(
                        SmartCardError.ConditionsNotSatisfied()
                    ),
            _
                => Result.Failure<IApplication, SmartCardError>(
                    SmartCardError.ConditionsNotSatisfied()
                ),
        };
    }

    private Result<IApplication, SmartCardError> ValidateSecurityRequirements(
        IApplication app,
        byte[] command,
        CardState cardState
    )
    {
        byte instruction = command[1];

        return app.GetRequiredPrivileges(instruction)
            .Match(
                requiredPrivileges =>
                {
                    // Check if application has required privileges
                    bool hasPrivileges =
                        (app.Privileges & requiredPrivileges) == requiredPrivileges;

                    // Additional security level validation per GP Table 11-2
                    bool hasSecurityLevel = ValidateSecurityLevel(instruction, cardState);

                    return hasPrivileges && hasSecurityLevel
                        ? Result.Success<IApplication, SmartCardError>(app)
                        : Result.Failure<IApplication, SmartCardError>(
                            SmartCardError.SecurityStatusNotSatisfied()
                        );
                },
                () => Result.Success<IApplication, SmartCardError>(app)
            ); // No special privileges required
    }

    private static bool ValidateSecurityLevel(byte instruction, CardState cardState)
    {
        // Per GP Card Specification Table 11-2
        return instruction switch
        {
            GpIns.GET_STATUS => cardState.SecurityLevel >= 0x01,
            GpIns.INSTALL => cardState.SecurityLevel >= 0x01,
            GpIns.LOAD => cardState.SecurityLevel >= 0x01,
            GpIns.DELETE => cardState.SecurityLevel >= 0x01,
            GpIns.PUT_KEY => cardState.SecurityLevel >= 0x01,
            GpIns.STORE_DATA => cardState.SecurityLevel >= 0x01,
            GpIns.SET_STATUS => cardState.SecurityLevel >= 0x01,
            _ => true, // Most commands don't require authenticated security level
        };
    }

    private Maybe<ImmutableArray<byte>> GetIsdAid()
    {
        // ISD is the application with SecurityDomain privilege
        var isdApps = Applications
            .Values.Where(app => (app.Privileges & Privilege.SecurityDomain) != 0)
            .ToImmutableList();

        return isdApps.Count > 0
            ? Maybe<ImmutableArray<byte>>.From(isdApps[0].Aid)
            : Maybe<ImmutableArray<byte>>.None;
    }

    #endregion
}

/// <summary>
/// Equality comparer for ImmutableArray&lt;byte&gt; used as AID keys.
/// </summary>
internal sealed class AidEqualityComparer : IEqualityComparer<ImmutableArray<byte>>
{
    public bool Equals(ImmutableArray<byte> x, ImmutableArray<byte> y)
    {
        return x.SequenceEqual(y);
    }

    public int GetHashCode(ImmutableArray<byte> obj)
    {
        return obj.Aggregate(0, (hash, b) => HashCode.Combine(hash, b));
    }
}
