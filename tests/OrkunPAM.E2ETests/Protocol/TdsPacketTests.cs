using OrkunPAM.SqlProxy.Protocol;

namespace OrkunPAM.E2ETests.Protocol;

/// <summary>
/// Unit-level E2E tests for the TDS (Tabular Data Stream) packet layer used by SqlProxy.
/// Uses MemoryStream to simulate the TCP stream without requiring a real SQL Server.
/// </summary>
public sealed class TdsPacketTests
{
    // ── Write → Read roundtrip ─────────────────────────────────────────────

    [Fact]
    [Trait("Category", "E2E")]
    public async Task TdsPacket_WriteAndRead_PreLoginRoundtrip()
    {
        var payload = new byte[] { 0x00, 0x01, 0x02, 0x03, 0xFF };
        var ms = new MemoryStream();

        await TdsPacket.WritePacketAsync(ms, TdsPacket.TypePreLogin, payload, CancellationToken.None);
        ms.Position = 0;

        var result = await TdsPacket.ReadAsync(ms, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(TdsPacket.TypePreLogin, result!.Value.type);
        Assert.Equal(TdsPacket.StatusEom, result.Value.status & TdsPacket.StatusEom);
        Assert.Equal(payload, result.Value.payload);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task TdsPacket_WriteAndRead_Login7Roundtrip()
    {
        var payload = Enumerable.Range(0, 64).Select(i => (byte)i).ToArray();
        var ms = new MemoryStream();

        await TdsPacket.WritePacketAsync(ms, TdsPacket.TypeLogin7, payload, CancellationToken.None);
        ms.Position = 0;

        var result = await TdsPacket.ReadAsync(ms, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(TdsPacket.TypeLogin7, result!.Value.type);
        Assert.Equal(payload, result.Value.payload);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task TdsPacket_EmptyPayload_WriteAndRead()
    {
        var ms = new MemoryStream();
        await TdsPacket.WritePacketAsync(ms, TdsPacket.TypeSqlBatch, [], CancellationToken.None);
        ms.Position = 0;

        var result = await TdsPacket.ReadAsync(ms, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(TdsPacket.TypeSqlBatch, result!.Value.type);
        Assert.Empty(result.Value.payload);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task TdsPacket_LargePayload_IntegrityPreserved()
    {
        var payload = new byte[32 * 1024];
        new Random(42).NextBytes(payload);

        var ms = new MemoryStream();
        await TdsPacket.WritePacketAsync(ms, TdsPacket.TypeSqlBatch, payload, CancellationToken.None);
        ms.Position = 0;

        var result = await TdsPacket.ReadAsync(ms, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(payload, result!.Value.payload);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task TdsPacket_ReadMessageAsync_SinglePacket()
    {
        var payload = new byte[] { 0xAA, 0xBB, 0xCC };
        var ms = new MemoryStream();
        await TdsPacket.WritePacketAsync(ms, TdsPacket.TypePreLogin, payload, CancellationToken.None);
        ms.Position = 0;

        var result = await TdsPacket.ReadMessageAsync(ms, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(TdsPacket.TypePreLogin, result!.Value.type);
        Assert.Equal(payload, result.Value.fullPayload);
        Assert.Single(result.Value.rawPackets);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task TdsPacket_HeaderLength_Correct()
    {
        var payload = new byte[] { 1, 2, 3 };
        var ms = new MemoryStream();
        await TdsPacket.WritePacketAsync(ms, TdsPacket.TypePreLogin, payload, CancellationToken.None);

        var bytes = ms.ToArray();
        int encodedLength = (bytes[2] << 8) | bytes[3];
        Assert.Equal(TdsPacket.HeaderSize + payload.Length, encodedLength);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task TdsPacket_ReadAsync_ClosedStream_ReturnsNull()
    {
        var ms = new MemoryStream([]);
        var result = await TdsPacket.ReadAsync(ms, CancellationToken.None);
        Assert.Null(result);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task TdsPacket_MultiplePackets_AllReadCorrectly()
    {
        var ms = new MemoryStream();
        for (int i = 0; i < 5; i++)
            await TdsPacket.WritePacketAsync(ms, TdsPacket.TypeSqlBatch,
                [(byte)i, (byte)(i * 2)], CancellationToken.None);
        ms.Position = 0;

        for (int i = 0; i < 5; i++)
        {
            var result = await TdsPacket.ReadAsync(ms, CancellationToken.None);
            Assert.NotNull(result);
            Assert.Equal((byte)i, result!.Value.payload[0]);
            Assert.Equal((byte)(i * 2), result.Value.payload[1]);
        }
    }
}
