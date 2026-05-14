using System.Numerics;
using OrkunPAM.SshProxy.Protocol;

namespace OrkunPAM.E2ETests.Protocol;

/// <summary>
/// Unit-level E2E tests for the SSH binary encoding layer (RFC 4253 data types).
/// SshEncoding operates on spans and MemoryStreams — no sockets required.
/// </summary>
public sealed class SshEncodingTests
{
    // ── UInt32 ─────────────────────────────────────────────────────

    [Fact]
    [Trait("Category", "E2E")]
    public void WriteUInt32_Span_BigEndian()
    {
        var buf = new byte[4];
        SshEncoding.WriteUInt32(buf.AsSpan(), 0, 0xDEADBEEF);

        Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, buf);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public void WriteReadUInt32_MemoryStream_Roundtrip()
    {
        var ms = new MemoryStream();
        SshEncoding.WriteUInt32(ms, 0x12345678u);

        var data = ms.ToArray();
        int offset = 0;
        uint value = SshEncoding.ReadUInt32(data.AsSpan(), ref offset);

        Assert.Equal(0x12345678u, value);
        Assert.Equal(4, offset);
    }

    [Theory]
    [Trait("Category", "E2E")]
    [InlineData(0u)]
    [InlineData(1u)]
    [InlineData(uint.MaxValue)]
    [InlineData(0x00FFFFFFu)]
    public void WriteReadUInt32_RoundtripValues(uint value)
    {
        var ms = new MemoryStream();
        SshEncoding.WriteUInt32(ms, value);

        var data = ms.ToArray();
        int offset = 0;
        uint decoded = SshEncoding.ReadUInt32(data.AsSpan(), ref offset);

        Assert.Equal(value, decoded);
    }

    // ── String ──────────────────────────────────────────────────────

    [Fact]
    [Trait("Category", "E2E")]
    public void WriteReadString_AsciiRoundtrip()
    {
        var ms = new MemoryStream();
        SshEncoding.WriteString(ms, "ssh-userauth");

        var data = ms.ToArray();
        int offset = 0;
        string decoded = SshEncoding.ReadString(data.AsSpan(), ref offset);

        Assert.Equal("ssh-userauth", decoded);
        Assert.Equal(4 + 12, offset);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public void WriteReadString_EmptyString()
    {
        var ms = new MemoryStream();
        SshEncoding.WriteString(ms, "");

        var data = ms.ToArray();
        int offset = 0;
        string decoded = SshEncoding.ReadString(data.AsSpan(), ref offset);

        Assert.Equal("", decoded);
        Assert.Equal(4, offset);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public void WriteReadString_UnicodeRoundtrip()
    {
        const string text = "OrkunPAM-パスワード管理";
        var ms = new MemoryStream();
        SshEncoding.WriteString(ms, text);

        var data = ms.ToArray();
        int offset = 0;
        string decoded = SshEncoding.ReadString(data.AsSpan(), ref offset);

        Assert.Equal(text, decoded);
    }

    // ── NameList ─────────────────────────────────────────────────────

    [Fact]
    [Trait("Category", "E2E")]
    public void WriteReadNameList_MultipleAlgorithms()
    {
        var ms = new MemoryStream();
        SshEncoding.WriteNameList(ms, "diffie-hellman-group14-sha256", "aes256-ctr", "hmac-sha2-256");

        var data = ms.ToArray();
        int offset = 0;
        string[] names = SshEncoding.ReadNameList(data.AsSpan(), ref offset);

        Assert.Equal(3, names.Length);
        Assert.Equal("diffie-hellman-group14-sha256", names[0]);
        Assert.Equal("aes256-ctr", names[1]);
        Assert.Equal("hmac-sha2-256", names[2]);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public void WriteReadNameList_SingleItem()
    {
        var ms = new MemoryStream();
        SshEncoding.WriteNameList(ms, "none");

        var data = ms.ToArray();
        int offset = 0;
        string[] names = SshEncoding.ReadNameList(data.AsSpan(), ref offset);

        Assert.Single(names);
        Assert.Equal("none", names[0]);
    }

    // ── ByteString ────────────────────────────────────────────────────

    [Fact]
    [Trait("Category", "E2E")]
    public void WriteReadByteString_Roundtrip()
    {
        var payload = new byte[] { 0x01, 0x02, 0x03, 0xDE, 0xAD };
        var ms = new MemoryStream();
        SshEncoding.WriteByteString(ms, payload);

        var data = ms.ToArray();
        int offset = 0;
        byte[] decoded = SshEncoding.ReadByteString(data.AsSpan(), ref offset);

        Assert.Equal(payload, decoded);
        Assert.Equal(4 + payload.Length, offset);
    }

    // ── MpInt ───────────────────────────────────────────────────────

    [Fact]
    [Trait("Category", "E2E")]
    public void WriteReadMpInt_Zero()
    {
        var ms = new MemoryStream();
        SshEncoding.WriteMpInt(ms, BigInteger.Zero);

        var data = ms.ToArray();
        int offset = 0;
        var decoded = SshEncoding.ReadMpInt(data.AsSpan(), ref offset);

        Assert.Equal(BigInteger.Zero, decoded);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public void WriteReadMpInt_LargePositive()
    {
        var value = BigInteger.Pow(2, 256) - 189;
        var ms = new MemoryStream();
        SshEncoding.WriteMpInt(ms, value);

        var data = ms.ToArray();
        int offset = 0;
        var decoded = SshEncoding.ReadMpInt(data.AsSpan(), ref offset);

        Assert.Equal(value, decoded);
    }

    // ── Bool ─────────────────────────────────────────────────────

    [Theory]
    [Trait("Category", "E2E")]
    [InlineData(true)]
    [InlineData(false)]
    public void WriteReadBool_Roundtrip(bool value)
    {
        var ms = new MemoryStream();
        SshEncoding.WriteBool(ms, value);

        var data = ms.ToArray();
        int offset = 0;
        bool decoded = SshEncoding.ReadBool(data.AsSpan(), ref offset);

        Assert.Equal(value, decoded);
        Assert.Equal(1, offset);
    }
}
