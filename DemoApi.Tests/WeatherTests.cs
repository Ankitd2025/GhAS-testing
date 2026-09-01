using Xunit;
using FluentAssertions;

namespace DemoApi.Tests;

public class WeatherTests
{
    [Fact]
    public void Test1()
    {
        int result = 2 + 2;

        result.Should().Be(4);
    }
}