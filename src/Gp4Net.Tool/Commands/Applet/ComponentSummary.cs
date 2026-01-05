using CSharpFunctionalExtensions;
using Gp4Net.Domain.CapFile;

namespace Gp4Net.Tool.Commands.Applet;

/// <summary>
/// Summary information for a CAP file component.
/// Immutable record following functional programming principles.
/// </summary>
public sealed record ComponentSummary
{
    /// <summary>
    /// Gets the component name (Header, Directory, Applet, etc.).
    /// </summary>
    public string Name { get; init; }

    /// <summary>
    /// Gets the component size in bytes.
    /// </summary>
    public int Size { get; init; }

    /// <summary>
    /// Gets the component tag from CAP file.
    /// </summary>
    public byte Tag { get; init; }

    /// <summary>
    /// Gets optional detailed information (e.g., number of classes, methods).
    /// </summary>
    public Maybe<string> Details { get; init; }

    private ComponentSummary(string name, int size, byte tag, Maybe<string> details)
    {
        Name = name;
        Size = size;
        Tag = tag;
        Details = details;
    }

    /// <summary>
    /// Creates a new component summary from a CAP component.
    /// </summary>
    public static ComponentSummary FromComponent(
        CapComponent component,
        Maybe<string> details = default
    )
    {
        return new ComponentSummary(
            GetComponentName(component.Tag),
            component.Data.Length,
            component.Tag,
            details
        );
    }

    /// <summary>
    /// Creates a new component summary with explicit values.
    /// </summary>
    public static ComponentSummary Create(
        string name,
        int size,
        byte tag,
        Maybe<string> details = default
    )
    {
        return new ComponentSummary(name, size, tag, details);
    }

    /// <summary>
    /// Maps component tag to human-readable name based on Java Card VM spec.
    /// </summary>
    private static string GetComponentName(byte tag) =>
        tag switch
        {
            1 => "Header",
            2 => "Directory",
            3 => "Applet",
            4 => "Import",
            5 => "ConstantPool",
            6 => "Class",
            7 => "Method",
            8 => "StaticField",
            9 => "ReferenceLocation",
            10 => "Export",
            11 => "Descriptor",
            12 => "Debug",
            _ => $"Unknown (0x{tag:X2})"
        };
}
