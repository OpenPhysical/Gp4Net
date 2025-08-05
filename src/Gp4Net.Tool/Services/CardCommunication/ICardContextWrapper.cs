using System;
using System.Collections.Generic;
using WSCT.Wrapper;

namespace Gp4Net.Tool.Services.CardCommunication;

/// <summary>
/// Wrapper interface for WSCT CardContext to enable unit testing.
/// </summary>
public interface ICardContextWrapper : IDisposable
{
    /// <summary>
    /// Gets the list of available readers.
    /// </summary>
    IReadOnlyList<string> Readers { get; }

    /// <summary>
    /// Establishes the resource manager context.
    /// </summary>
    /// <returns>Error code indicating success or failure.</returns>
    ErrorCode Establish();

    /// <summary>
    /// Lists all available card readers.
    /// </summary>
    /// <param name="groups">Reader groups to list (empty string for all).</param>
    /// <returns>Error code indicating success or failure.</returns>
    ErrorCode ListReaders(string groups);

    /// <summary>
    /// Creates a new card channel for the specified reader.
    /// </summary>
    /// <param name="readerName">Name of the reader.</param>
    /// <returns>A new card channel instance.</returns>
    ICardChannelWrapper CreateCardChannel(string readerName);

    /// <summary>
    /// Releases the resource manager context.
    /// </summary>
    /// <returns>Error code indicating success or failure.</returns>
    ErrorCode Release();
}