using BenchmarkDotNet.Attributes;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;

namespace Gp4Net.Benchmarks;

[MemoryDiagnoser]
[SimpleJob(iterationCount: 100)]
public class DeleteCommandBenchmarks
{
    private static readonly byte[] TestAid = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];

    [Benchmark]
    public Result<DeleteCommand, SmartCardError> CreateDeleteApplicationCommand()
    {
        return DeleteCommand.CreateForApplication(TestAid);
    }

    [Benchmark]
    public Result<DeleteCommand, SmartCardError> CreateDeletePackageCommand()
    {
        return DeleteCommand.CreateForPackage(TestAid);
    }

    [Benchmark]
    public Result<byte[], SmartCardError> BuildApdu()
    {
        return DeleteCommand.CreateForApplication(TestAid).Map(cmd => cmd.ToBytes());
    }
}
