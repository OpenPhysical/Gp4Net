using BenchmarkDotNet.Attributes;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.Commands;

namespace Gp4Net.Benchmarks;

[MemoryDiagnoser]
[SimpleJob(iterationCount: 100)]
public class ApduProcessingBenchmarks
{
    private static readonly byte[] TestAid = [0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00];

    [Benchmark]
    public Result<SelectCommand, SmartCardError> CreateSelectCommand()
    {
        return SelectCommand.Create(TestAid);
    }

    [Benchmark]
    public Result<GetStatusCommand, SmartCardError> CreateGetStatusCommand()
    {
        return GetStatusCommand.Create(
            GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
            GetStatusCommand.ResponseFormat.None,
            Maybe<byte[]>.None
        );
    }

    [Benchmark]
    public Result<DeleteCommand, SmartCardError> CreateDeleteCommand()
    {
        return DeleteCommand.CreateForApplication(TestAid);
    }

    [Benchmark]
    public Result<byte[], SmartCardError> BuildSelectApdu()
    {
        return SelectCommand.Create(TestAid).Map(cmd => cmd.ToBytes());
    }

    [Benchmark]
    public Result<byte[], SmartCardError> BuildGetStatusApdu()
    {
        return GetStatusCommand
            .Create(
                GetStatusCommand.StatusSubset.ApplicationsAndSupplementaryDomains,
                GetStatusCommand.ResponseFormat.None,
                Maybe<byte[]>.None
            )
            .Map(cmd => cmd.ToBytes());
    }

    [Benchmark]
    public Result<byte[], SmartCardError> BuildDeleteApdu()
    {
        return DeleteCommand.CreateForApplication(TestAid).Map(cmd => cmd.ToBytes());
    }
}
