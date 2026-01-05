using BenchmarkDotNet.Attributes;
using CSharpFunctionalExtensions;
using Gp4Net.Core;
using Gp4Net.Domain.CapFile;

namespace Gp4Net.Benchmarks;

[MemoryDiagnoser]
[SimpleJob(iterationCount: 100)]
public class CapFileBenchmarks
{
    private byte[] _smallCapFile = [];
    private byte[] _mediumCapFile = [];
    private byte[] _largeCapFile = [];

    [GlobalSetup]
    public void Setup()
    {
        _smallCapFile = GenerateCapFile(1024);
        _mediumCapFile = GenerateCapFile(8192);
        _largeCapFile = GenerateCapFile(32768);
    }

    [Benchmark]
    public Result<CapFileStructure, SmartCardError> ParseSmallCapFile()
    {
        return CapFileStructure.Parse(_smallCapFile);
    }

    [Benchmark]
    public Result<CapFileStructure, SmartCardError> ParseMediumCapFile()
    {
        return CapFileStructure.Parse(_mediumCapFile);
    }

    [Benchmark]
    public Result<CapFileStructure, SmartCardError> ParseLargeCapFile()
    {
        return CapFileStructure.Parse(_largeCapFile);
    }

    [Benchmark]
    public Result<CapFileStructure, SmartCardError> ValidateCapDetailed()
    {
        return CapFileStructure.Parse(_mediumCapFile);
    }

    private static byte[] GenerateCapFile(int size)
    {
        byte[] data = new byte[size];
        data[0] = 0x50;
        data[1] = 0x4B;
        data[2] = 0x03;
        data[3] = 0x04;
        return data;
    }
}
