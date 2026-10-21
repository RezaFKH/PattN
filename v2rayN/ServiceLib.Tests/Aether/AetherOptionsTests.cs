namespace ServiceLib.Tests.Aether;

public class AetherOptionsTests
{
    /// <summary>The number of each TLS 1.2 suite by the name BoringSSL gives it, for the ones the fingerprints name.</summary>
    private static readonly Dictionary<string, int> SuiteIds = new()
    {
        ["ECDHE-ECDSA-AES128-GCM-SHA256"] = 0xc02b,
        ["ECDHE-RSA-AES128-GCM-SHA256"] = 0xc02f,
        ["ECDHE-ECDSA-AES256-GCM-SHA384"] = 0xc02c,
        ["ECDHE-RSA-AES256-GCM-SHA384"] = 0xc030,
        ["ECDHE-ECDSA-CHACHA20-POLY1305"] = 0xcca9,
        ["ECDHE-RSA-CHACHA20-POLY1305"] = 0xcca8,
        ["ECDHE-RSA-AES128-SHA"] = 0xc013,
        ["ECDHE-RSA-AES256-SHA"] = 0xc014,
        ["ECDHE-ECDSA-AES128-SHA"] = 0xc009,
        ["ECDHE-ECDSA-AES256-SHA"] = 0xc00a,
        ["ECDHE-ECDSA-AES128-SHA256"] = 0xc023,
        ["ECDHE-RSA-AES128-SHA256"] = 0xc027,
        ["AES128-GCM-SHA256"] = 0x009c,
        ["AES256-GCM-SHA384"] = 0x009d,
        ["AES128-SHA"] = 0x002f,
        ["AES256-SHA"] = 0x0035,
    };

    /// <summary>The TLS 1.2 suites of a ClientHello's cipher_suites in hex, GREASE and the TLS 1.3 suites left out.</summary>
    private static List<int> Tls12Of(string captured)
    {
        return captured.Chunk(4)
            .Select(chunk => Convert.ToInt32(new string(chunk), 16))
            .Where(suite => (suite & 0x0f0f) != 0x0a0a && suite is not (>= 0x1301 and <= 0x1305))
            .ToList();
    }

    private static List<int> SuitesOf(AetherFingerprint fingerprint)
    {
        return fingerprint.Ciphers.Split(':').Select(name => SuiteIds[name]).ToList();
    }

    // From PattNG AetherFmtTest; the assertion on a link written before the rename goes with AetherFmt.
    [Test]
    public async Task TheOldNameOfTheVerifiedScanModeStillReads()
    {
        await AetherScanMode.FromString("stealth").Should().BeEqualTo(AetherScanMode.Verified);
        await AetherScanMode.FromString("verified").Should().BeEqualTo(AetherScanMode.Verified);
        await AetherScanMode.FromString("quiet").Should().BeEqualTo(AetherScanMode.Balanced);
    }

    // From PattNG AetherKeysTest.
    [Test]
    public async Task AKindStoredBeforeWireGuardOverMasqueKeepsItsKeys()
    {
        // The page stored the type of the protocol; WARP-in-WARP's keys are still both WireGuard hops' ones.
        await AetherKeyKind.FromString("gool").Should().BeEqualTo(AetherKeyKind.Gool);
        await AetherKeyKind.Gool.Register.Should().BeEqualTo("gool-classic");
        await AetherKeyKind.FromString("wg-over-masque").Should().BeEqualTo(AetherKeyKind.WgOverMasque);
        await AetherKeyKind.FromString(null).Should().BeEqualTo(AetherKeyKind.AllKeys);
    }

    // From PattNG AetherKeysTest.
    [Test]
    public async Task EachFingerprintOffersTheTls12SuitesOfItsCapturedClientHello()
    {
        // The ClientHellos captured with Wireshark. Chrome's, eaea130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035,
        // comes from Chrome's own rule, which BoringSSL orders by the machine's AES instructions as it does the TLS 1.3
        // suites: these twelve with them, ChaCha20 first without (both seen on boring 5.2.0). So Chrome names its rule,
        // as Chromium sets it, and keeps GREASE.
        await AetherFingerprint.Chrome.Ciphers.Should().BeEqualTo("ALL:!aPSK:!ECDSA+SHA1:!3DES");
        await AetherFingerprint.Chrome.Arguments.SequenceEqual(["--tls-ciphers", "ALL:!aPSK:!ECDSA+SHA1:!3DES"]).Should().BeTrue();
        await SuitesOf(AetherFingerprint.Firefox).SequenceEqual(Tls12Of("130113031302c02bc02fcca9cca8c02cc030c013c014009c009d002f0035")).Should().BeTrue();
        // Python's first ten, with c00a and c014 (AES-256-CBC with SHA-1) in place of c024 and c028 (with SHA-384),
        // which BoringSSL does not have; its four DHE suites after them are left out.
        var nearest = new Dictionary<int, int> { [0xc024] = 0xc00a, [0xc028] = 0xc014 };
        var python = Tls12Of("130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b0067")
            .Take(10)
            .Select(suite => nearest.GetValueOrDefault(suite, suite));
        await SuitesOf(AetherFingerprint.SemiPython).SequenceEqual(python).Should().BeTrue();
        // Go lists its TLS 1.3 suites last, which BoringSSL cannot do; its TLS 1.2 suites are all there.
        await SuitesOf(AetherFingerprint.Go).SequenceEqual(Tls12Of("c02bc02fc02cc030cca9cca8c009c013c00ac014130113021303")).Should().BeTrue();
    }

    // From PattNG AetherKeysTest; the check of AetherKeys.arguments for every fingerprint goes with AetherKeys.
    [Test]
    public async Task OnlyChromeSendsGrease()
    {
        await AetherFingerprint.Chrome.Grease.Should().BeTrue();
        await AetherFingerprint.Firefox.Grease.Should().BeFalse();
        await AetherFingerprint.SemiPython.Grease.Should().BeFalse();
        await AetherFingerprint.Go.Grease.Should().BeFalse();
    }

    // From PattNG AetherKeysTest. Its check of the dropdown's labels (Chrome, Firefox, Semi-Python, Go) against this
    // order goes with the editor and the WARP keys window, which list them by their index in All.
    [Test]
    public async Task TheFingerprintListNamesEveryFingerprintInItsOrder()
    {
        await AetherFingerprint.All.Select(it => it.Type).SequenceEqual(["chrome", "firefox", "semi-python", "go"]).Should().BeTrue();
        await AetherFingerprint.FromString("semi-python").Should().BeEqualTo(AetherFingerprint.SemiPython);
    }
}
