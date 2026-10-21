namespace ServiceLib.Tests.Aether;

public class AetherLogLineTests
{
    [Test]
    public async Task CoreOutputKeepsItsLogLevel()
    {
        await AetherLogLine.OutputPriority("[2026-09-11T10:00:00.000Z ERROR aether] config parse failed").Should().BeEqualTo(AetherLogPriority.Error);
        await AetherLogLine.OutputPriority("[2026-09-11T10:00:00.000Z WARN  aether] [-] tunnel ended").Should().BeEqualTo(AetherLogPriority.Warn);
        await AetherLogLine.OutputPriority("[2026-09-11T10:00:00.000Z INFO  aether] [+] identity ready").Should().BeEqualTo(AetherLogPriority.Info);
        await AetherLogLine.OutputPriority("[2026-09-11T10:00:00.000Z DEBUG aether::quic] packet").Should().BeEqualTo(AetherLogPriority.Debug);
        await AetherLogLine.OutputPriority("[2026-09-11T10:00:00.000Z TRACE aether] packet").Should().BeEqualTo(AetherLogPriority.Debug);
    }

    [Test]
    public async Task AFatalErrorFromTheCoreIsAnError()
    {
        await AetherLogLine.OutputPriority("Error: Api(\"too many registrations\")").Should().BeEqualTo(AetherLogPriority.Error);
    }

    [Test]
    public async Task TheLogHeaderIsStrippedFromCoreOutput()
    {
        await AetherLogLine.OutputMessage("[2026-09-11T10:00:00.000Z INFO  aether::prober] [+] candidate ok 162.159.197.3:443 rtt=84ms")
            .Should().BeEqualTo("[+] candidate ok 162.159.197.3:443 rtt=84ms");
        await AetherLogLine.OutputMessage("[+] selected protocol: MASQUE").Should().BeEqualTo("[+] selected protocol: MASQUE");
        await AetherLogLine.OutputMessage("  fallback over tcp 443  ").Should().BeEqualTo("fallback over tcp 443");
        await AetherLogLine.OutputMessage("   ").Should().BeEqualTo("");
    }

    [Test]
    public async Task OutputWithoutALogHeaderIsInformational()
    {
        await AetherLogLine.OutputPriority("  fallback over tcp 443 (--masque-http2) on this network.").Should().BeEqualTo(AetherLogPriority.Info);
        await AetherLogLine.OutputPriority("[unterminated header").Should().BeEqualTo(AetherLogPriority.Info);
        await AetherLogLine.OutputPriority("[]").Should().BeEqualTo(AetherLogPriority.Info);
    }

    // PattNG's test also checks AetherCoreManager.readyNeedsWord and showsInfo, which AetherArguments ports; only the
    // ready word is here.
    [Test]
    public async Task WhereTheAppDialsPsiphonReadinessNeedsTheCoresWord()
    {
        await AetherLogLine.IsReadyWord("[2026-09-24T10:00:00.000Z INFO  aether] [+] psiphon is ready; 127.0.0.1:10829 leaves through psiphon, carried by the tunnel").Should().BeTrue();
        await AetherLogLine.IsReadyWord("[2026-09-24T10:00:00.000Z INFO  aether] [+] psiphon is ready; 127.0.0.1:10829 leaves through psiphon").Should().BeTrue();
        await AetherLogLine.IsReadyWord("[2026-09-24T10:00:00.000Z INFO  aether] [*] starting psiphon through the tunnel at 127.0.0.1:10830").Should().BeFalse();
        await AetherLogLine.IsReadyWord("[2026-09-24T10:00:00.000Z INFO  aether] [+] psiphon reached a server at 203.0.113.9").Should().BeFalse();
    }

    // PattNG's test also checks AetherCoreManager.stoppedMessage, a string resource of a later stage; only the word and
    // the level of the line are here.
    [Test]
    public async Task ACoreThatStoppedForWantOfAnEchKeyIsReportedSo()
    {
        // The core's last line as its main prints the error it ends with (fork aether/src/lib.rs, session_ech_key).
        const string stopped = "Error: Ech(\"ECH is on but there is no ECH key to offer (udp://1.1.1.1:53 did not answer for "
                               + "cloudflare-ech.com); stopping rather than send the server name in the clear\")";
        await AetherLogLine.IsNoEchKeyWord(stopped).Should().BeTrue();
        await AetherLogLine.OutputPriority(stopped).Should().BeEqualTo(AetherLogPriority.Error);
        await AetherLogLine.IsNoEchKeyWord("[2026-10-01T10:00:00.000Z INFO  aether] [+] fetched ECHConfigList automatically (71 bytes)").Should().BeFalse();
        await AetherLogLine.IsNoEchKeyWord("[2026-10-01T10:00:00.000Z INFO  aether] [+] ECH off; the server name goes out in cleartext").Should().BeFalse();
        await AetherLogLine.IsNoEchKeyWord("Error: Api(\"too many registrations\")").Should().BeFalse();
    }

    // PattN only (design 2.6.1): the Tor logs of the core can carry colour codes even when piped.
    [Test]
    public async Task AnsiColourCodesAreStrippedFromCoreOutput()
    {
        const string coloured = "\u001b[2m2026-10-20T10:00:00.123456Z\u001b[0m \u001b[32m INFO\u001b[0m \u001b[2marti_client\u001b[0m: bootstrapped";
        await AetherLogLine.StripAnsi(coloured).Should().BeEqualTo("2026-10-20T10:00:00.123456Z  INFO arti_client: bootstrapped");
        await AetherLogLine.StripAnsi("[+] psiphon is ready").Should().BeEqualTo("[+] psiphon is ready");
    }
}
