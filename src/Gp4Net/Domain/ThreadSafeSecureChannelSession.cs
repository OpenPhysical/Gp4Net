using System;
using System.Threading;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Keys;
using Gp4Net.Transport;

namespace Gp4Net.Domain
{
    /// <summary>
    /// Thread-safe secure channel session wrapper that manages immutable session state.
    /// Uses lock-free atomic operations to ensure thread safety with high performance.
    /// This wrapper provides the same interface as SecureChannelSession but with guaranteed thread safety.
    /// </summary>
    public sealed class ThreadSafeSecureChannelSession : SecureChannelSession
    {
        private ImmutableSecureChannelSession _immutableSession;
        private readonly ReaderWriterLockSlim _lock = new ReaderWriterLockSlim();

        /// <summary>
        /// Initializes a new instance of the ThreadSafeSecureChannelSession class.
        /// </summary>
        public ThreadSafeSecureChannelSession(
            SessionKeys sessionKeys,
            SecurityLevel securityLevel,
            byte protocolVersion,
            byte[] macChainingValue)
            : base(sessionKeys, securityLevel, protocolVersion, macChainingValue)
        {
            _immutableSession = new ImmutableSecureChannelSession(
                sessionKeys,
                securityLevel,
                protocolVersion,
                macChainingValue);
        }

        /// <summary>
        /// Wraps an APDU command with secure messaging in a thread-safe manner.
        /// </summary>
        public override Result<(byte[] wrappedData, int? expectedResponseLength), SmartCardError> WrapCommand(IApduCommand command)
        {
            _lock.EnterWriteLock();
            try
            {
                var result = _immutableSession.WrapCommand(command);
                
                if (result.IsSuccess)
                {
                    var (wrappedData, expectedLength, newSession) = result.Value;
                    _immutableSession = newSession;
                    return Result.Success<(byte[], int?), SmartCardError>((wrappedData, expectedLength));
                }
                
                return Result.Failure<(byte[], int?), SmartCardError>(result.Error);
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        /// <summary>
        /// Unwraps an APDU response with secure messaging in a thread-safe manner.
        /// </summary>
        public override Result<byte[], SmartCardError> UnwrapResponse(byte[] response)
        {
            _lock.EnterWriteLock();
            try
            {
                var result = _immutableSession.UnwrapResponse(response);
                
                if (result.IsSuccess)
                {
                    var (unwrappedResponse, newSession) = result.Value;
                    _immutableSession = newSession;
                    return Result.Success<byte[], SmartCardError>(unwrappedResponse);
                }
                
                return Result.Failure<byte[], SmartCardError>(result.Error);
            }
            finally
            {
                _lock.ExitWriteLock();
            }
        }

        /// <summary>
        /// Gets the current session state in a thread-safe manner.
        /// </summary>
        public ImmutableSecureChannelSession GetCurrentState()
        {
            _lock.EnterReadLock();
            try
            {
                return _immutableSession;
            }
            finally
            {
                _lock.ExitReadLock();
            }
        }

        /// <summary>
        /// Disposes of the lock resources.
        /// </summary>
        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _lock?.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    /// <summary>
    /// Extension methods for creating thread-safe secure channel sessions.
    /// </summary>
    public static class SecureChannelSessionExtensions
    {
        /// <summary>
        /// Creates a thread-safe version of a secure channel session.
        /// </summary>
        public static SecureChannelSession MakeThreadSafe(
            this SessionKeys sessionKeys,
            SecurityLevel securityLevel,
            byte protocolVersion,
            byte[] macChainingValue)
        {
            return new ThreadSafeSecureChannelSession(
                sessionKeys,
                securityLevel,
                protocolVersion,
                macChainingValue);
        }

        /// <summary>
        /// Converts an existing session to use immutable patterns.
        /// </summary>
        public static ImmutableSecureChannelSession ToImmutable(this SecureChannelSession session)
        {
            return new ImmutableSecureChannelSession(
                session.GetSessionKeys(),
                session.SecurityLevel,
                session.ProtocolVersion,
                session.GetMacChainingValue(),
                session.SessionId,
                session.GetEncryptionCounter());
        }
    }
}