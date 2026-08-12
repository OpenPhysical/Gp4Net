using System.IO;
using System.Threading.Tasks;
using AwesomeAssertions;
using CSharpFunctionalExtensions;
using Gp4Net.Domain.CapFile;
using Gp4Net.Services;
using Gp4Net.Tool.Commands.Applet;
using Gp4Net.Tool.Commands.Common;
using NUnit.Framework;

namespace Gp4Net.Tests.Tool.Commands.Applet;

/// <summary>
/// Tests for ValidateCommand enhanced output features (User Story 2).
/// Tests JSON output format option.
/// Note: ValidateCommand is a simple AsyncCommand without complex dependencies,
/// so we test it directly via Spectre.Console.Cli framework.
/// </summary>
[TestFixture]
public sealed class ValidateCliCommandTests
{
    private string _testCapFilePath = string.Empty;

    [SetUp]
    public void Setup()
    {
        _testCapFilePath = Path.Combine(
            TestContext.CurrentContext.TestDirectory,
            "..",
            "..",
            "..",
            "..",
            "TestData",
            "caps",
            "uninstall-tests",
            "OpenFIPS201-v1_10_2.cap"
        );
    }

    [Test]
    public void Should_Have_Format_Option_Default_To_Table()
    {
        var settings = new ValidateCommand.Settings();

        _ = settings.Format.Should().Be(OutputFormat.Table);
    }

    [Test]
    public void Should_Allow_Format_Json_Option()
    {
        var settings = new ValidateCommand.Settings { Format = OutputFormat.Json };

        _ = settings.Format.Should().Be(OutputFormat.Json);
    }

    [Test]
    public void Should_Have_Detailed_Flag_Default_To_False()
    {
        var settings = new ValidateCommand.Settings();

        _ = settings.Detailed.Should().BeFalse();
    }

    [Test]
    public void Should_Allow_Detailed_Flag_To_Be_Set()
    {
        var settings = new ValidateCommand.Settings { Detailed = true };

        _ = settings.Detailed.Should().BeTrue();
    }

    [Test]
    public void Should_Parse_Empty_Static_Field_Component_Layout()
    {
        byte[] data = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        var result = StaticFieldComponentAnalysis.Parse(data);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.ComponentBodySize.Should().Be(10);
        _ = result.Value.ImageSize.Should().Be(0);
        _ = result.Value.ReferenceCount.Should().Be(0);
        _ = result.Value.ArrayInitCount.Should().Be(0);
        _ = result.Value.DefaultValueCount.Should().Be(0);
        _ = result.Value.NonDefaultValueCount.Should().Be(0);
        _ = result.Value.InitializedArrays.Should().BeEmpty();
        _ = result.Value.NonDefaultValues.Should().BeEmpty();
    }

    [Test]
    public void Should_Parse_Static_Field_Arrays_And_Non_Default_Values()
    {
        byte[] data =
        [
            0x00,
            0x08, // image_size
            0x00,
            0x02, // reference_count
            0x00,
            0x01, // array_init_count
            0x03, // byte[]
            0x00,
            0x03, // array value count
            0xAA,
            0xBB,
            0xCC,
            0x00,
            0x04, // default_value_count
            0x00,
            0x02, // non_default_value_count
            0x11,
            0x22,
        ];

        var result = StaticFieldComponentAnalysis.Parse(data);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.ImageSize.Should().Be(8);
        _ = result.Value.ReferenceCount.Should().Be(2);
        _ = result.Value.ArrayInitCount.Should().Be(1);
        _ = result.Value.InitializedArrays.Should().ContainSingle();
        _ = result.Value.InitializedArrays[0].Type.Should().Be(0x03);
        _ = result.Value.InitializedArrays[0].Values.Should().Equal(0xAA, 0xBB, 0xCC);
        _ = result.Value.DefaultValueCount.Should().Be(4);
        _ = result.Value.NonDefaultValueCount.Should().Be(2);
        _ = result.Value.NonDefaultValues.Should().Equal(0x11, 0x22);
        _ = result.Value.TrailingByteCount.Should().Be(0);
    }

    [Test]
    public void Should_Parse_Manifest_Continuation_Lines_For_Long_Import_Aids()
    {
        const string manifest = """
            Manifest-Version: 1.0
            Java-Card-Imported-Package-1-AID: 0xd2:0x76:0x00:0x00:0x85:0x30:0x4a:0x4
             3:0x4f:0x50:0x58
            Java-Card-Imported-Package-1-Version: 1.24
            """;

        var parsed = ManifestInfo.Parse(manifest);

        _ = parsed.ImportedPackages.Should().ContainSingle();
        _ = parsed
            .ImportedPackages[0]
            .Aid.Should()
            .Be("0xd2:0x76:0x00:0x00:0x85:0x30:0x4a:0x43:0x4f:0x50:0x58");
    }

    [Test]
    public void Should_Parse_Export_Component_And_Correlate_Descriptor_Method_Metadata()
    {
        var capFile = CreateCapFile(
            new CapComponent(
                Constants.Constants.JavaCard.ComponentTags.EXPORT,
                9,
                [0x01, 0x00, 0x10, 0x01, 0x01, 0x00, 0x04, 0x00, 0x20]
            ),
            new CapComponent(
                Constants.Constants.JavaCard.ComponentTags.DESCRIPTOR,
                31,
                [
                    0x01, // class_count
                    0x00, // token
                    0x11, // public final class
                    0x00,
                    0x10, // this_class_ref
                    0x00, // interface_count
                    0x00,
                    0x01, // field_count
                    0x00,
                    0x01, // method_count
                    0x00, // field token
                    0x09, // public static field
                    0x00,
                    0x00,
                    0x04, // static field image offset
                    0x80,
                    0x03, // primitive byte type
                    0x00, // token
                    0x09, // public static
                    0x00,
                    0x20, // method_offset
                    0x00,
                    0x12, // type_offset
                    0x00,
                    0x05, // bytecode_count
                    0x00,
                    0x00, // exception_handler_count
                    0x00,
                    0x00, // exception_handler_index
                    0x00,
                    0x00, // type descriptor count
                ]
            ),
            new CapComponent(
                Constants.Constants.JavaCard.ComponentTags.METHOD,
                34,
                [
                    0x00, // handler_count
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x02, // compact method header: flags=0, max_stack=2
                    0x31, // nargs=3, max_locals=1
                ]
            )
        );

        var result = ExportComponentAnalysis.Parse(capFile);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Classes.Should().ContainSingle();
        _ = result.Value.StaticFieldCount.Should().Be(1);
        _ = result.Value.StaticMethodCount.Should().Be(1);

        var exportedClass = result.Value.Classes[0];
        _ = exportedClass.Token.Should().Be(0);
        _ = exportedClass.ClassOffset.Should().Be(0x0010);
        _ = exportedClass.Descriptor.HasValue.Should().BeTrue();
        _ = exportedClass.Descriptor.Value.AccessFlags.Should().Be(0x11);
        _ = exportedClass.StaticFields[0].StaticFieldImageOffset.Should().Be(0x0004);

        var method = exportedClass.StaticMethods[0];
        _ = method.Token.Should().Be(0);
        _ = method.MethodOffset.Should().Be(0x0020);
        _ = method.Descriptor.HasValue.Should().BeTrue();
        _ = method.Descriptor.Value.AccessFlags.Should().Be(0x09);
        _ = method.Descriptor.Value.BytecodeCount.Should().Be(5);
        _ = method.MethodHeader.HasValue.Should().BeTrue();
        _ = method.MethodHeader.Value.MaxStack.Should().Be(2);
        _ = method.MethodHeader.Value.ArgumentCount.Should().Be(3);
        _ = method.MethodHeader.Value.MaxLocals.Should().Be(1);
    }

    [Test]
    public void Should_Parse_Constant_Pool_And_Resolve_External_Package_Tokens()
    {
        var capFile = CreateCapFile(
            new CapComponent(
                Constants.Constants.JavaCard.ComponentTags.IMPORT,
                12,
                [
                    0x01, // package_count
                    0x06, // minor
                    0x01, // major
                    0x07, // aid_length
                    0xA0,
                    0x00,
                    0x00,
                    0x00,
                    0x62,
                    0x01,
                    0x01,
                ]
            ),
            new CapComponent(
                Constants.Constants.JavaCard.ComponentTags.CONSTANT_POOL,
                8,
                [
                    0x00,
                    0x02, // count
                    0x01,
                    0x00,
                    0x10,
                    0x00, // internal class ref
                    0x06,
                    0x80,
                    0x02,
                    0x03, // external static method ref
                ]
            )
        );

        var result = ConstantPoolComponentAnalysis.Parse(capFile, new PackageCatalog());

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Entries.Should().HaveCount(2);
        _ = result.Value.Entries[0].Kind.Should().Be(ConstantPoolEntryKind.Class);
        _ = result.Value.Entries[0].Target.InternalOffset.Value.Should().Be(0x0010);
        _ = result.Value.Entries[1].Kind.Should().Be(ConstantPoolEntryKind.StaticMethod);
        _ = result.Value.Entries[1].Target.PackageToken.Value.Should().Be(0x80);
        _ = result.Value.Entries[1].Target.ClassToken.Value.Should().Be(0x02);
        _ = result.Value.Entries[1].Target.MemberToken.Value.Should().Be(0x03);
        _ = result
            .Value.Entries[1]
            .Target.ImportedPackage.Value.AidHex.Should()
            .Be("A0000000620101");
    }

    [Test]
    public void Should_Parse_Reference_Locations_And_Join_Constant_Pool_Entries()
    {
        var capFile = CreateCapFile(
            new CapComponent(
                Constants.Constants.JavaCard.ComponentTags.CONSTANT_POOL,
                9,
                [
                    0x00,
                    0x02, // count
                    0x01,
                    0x00,
                    0x10,
                    0x00, // entry 0
                    0x01,
                    0x00,
                    0x20,
                    0x00, // entry 1
                ]
            ),
            new CapComponent(
                Constants.Constants.JavaCard.ComponentTags.METHOD,
                4,
                [0x00, 0x00, 0x00, 0x01]
            ),
            new CapComponent(
                Constants.Constants.JavaCard.ComponentTags.REFERENCE_LOCATION,
                6,
                [
                    0x00,
                    0x01, // byte_index_count
                    0x02, // method offset 2 -> cp index 0
                    0x00,
                    0x01, // byte2_index_count
                    0x02, // method offset 2 -> cp index 1
                ]
            )
        );
        var constantPool = ConstantPoolComponentAnalysis.Parse(capFile, new PackageCatalog()).Value;

        var result = ReferenceLocationComponentAnalysis.Parse(capFile, constantPool);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Sites.Should().HaveCount(2);
        _ = result.Value.Sites[0].ConstantPoolIndex.Should().Be(0);
        _ = result.Value.Sites[0].OperandWidth.Should().Be(ReferenceOperandWidth.OneByte);
        _ = result.Value.Sites[1].ConstantPoolIndex.Should().Be(1);
        _ = result.Value.Sites[1].OperandWidth.Should().Be(ReferenceOperandWidth.TwoByte);
        _ = result.Value.Groups.Should().HaveCount(2);
    }

    [Test]
    public void Should_Parse_Descriptor_Component_With_Field_Method_And_Header_Metadata()
    {
        var capFile = CreateCapFile(
            new CapComponent(
                Constants.Constants.JavaCard.ComponentTags.DESCRIPTOR,
                33,
                [
                    0x01, // class_count
                    0x02, // class token
                    0x11, // public final class
                    0x00,
                    0x20, // this_class_ref
                    0x01, // interface_count
                    0x00,
                    0x01, // field_count
                    0x00,
                    0x01, // method_count
                    0x80,
                    0x01, // interface ref
                    0x03, // field token
                    0x09, // public static
                    0x00,
                    0x00,
                    0x04, // static image offset
                    0x80,
                    0x03, // byte
                    0x04, // method token
                    0x01, // public
                    0x00,
                    0x10, // method offset
                    0x00,
                    0x20, // type offset
                    0x00,
                    0x03, // bytecode count
                    0x00,
                    0x00, // handlers
                    0x00,
                    0x00, // handler index
                    0x00,
                    0x00, // type descriptor count
                ]
            ),
            new CapComponent(
                Constants.Constants.JavaCard.ComponentTags.METHOD,
                18,
                [
                    0x00, // handler count
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x00,
                    0x21, // method offset 0x10: stack 1
                    0x20, // args 2, locals 0
                ]
            )
        );

        var result = DescriptorComponentAnalysis.Parse(capFile);

        _ = result.IsSuccess.Should().BeTrue();
        _ = result.Value.Classes.Should().ContainSingle();
        var classInfo = result.Value.Classes[0];
        _ = classInfo.Token.Should().Be(0x02);
        _ = classInfo.Interfaces.Should().Equal(0x8001);
        _ = classInfo.Fields.Should().ContainSingle();
        _ = classInfo.Fields[0].Reference.StaticFieldImageOffset.Value.Should().Be(0x0004);
        _ = classInfo.Fields[0].TypeReference.PrimitiveType.Value.Should().Be(0x03);
        _ = classInfo.Methods.Should().ContainSingle();
        _ = classInfo.Methods[0].MethodHeader.Value.MaxStack.Should().Be(1);
        _ = classInfo.Methods[0].MethodHeader.Value.ArgumentCount.Should().Be(2);
    }

    private static CapFileStructure CreateCapFile(params CapComponent[] components) =>
        new(
            [0xA0, 0x00, 0x00, 0x00, 0x01],
            new CapVersion(1, 0),
            components,
            [],
            Maybe<ManifestInfo>.None,
            new CapVersion(2, 1),
            0
        );
}
