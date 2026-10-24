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

    /// <summary>The number of each group by the name BoringSSL gives it, for every group it has (boring 5.3, with its post-quantum patch).</summary>
    private static readonly Dictionary<string, int> GroupIds = new()
    {
        ["P-256"] = 0x0017,
        ["P-384"] = 0x0018,
        ["P-521"] = 0x0019,
        ["X25519"] = 0x001d,
        ["X25519MLKEM768"] = 0x11ec,
        ["MLKEM1024"] = 0x0202,
        ["X25519Kyber768Draft00"] = 0x6399,
        ["P256Kyber768Draft00"] = 0xfe32,
    };

    /// <summary>The number of each TLS 1.3 suite by its standard name.</summary>
    private static readonly Dictionary<string, int> Tls13Ids = new()
    {
        ["TLS_AES_128_GCM_SHA256"] = 0x1301,
        ["TLS_AES_256_GCM_SHA384"] = 0x1302,
        ["TLS_CHACHA20_POLY1305_SHA256"] = 0x1303,
    };

    /// <summary>The TLS 1.3 suites of a ClientHello's cipher_suites in hex, in order.</summary>
    private static List<int> Tls13Of(string captured)
    {
        return captured.Chunk(4)
            .Select(chunk => Convert.ToInt32(new string(chunk), 16))
            .Where(suite => suite is >= 0x1301 and <= 0x1305)
            .ToList();
    }

    /// <summary>The groups of a ClientHello's supported_groups in hex that BoringSSL has, in order: GREASE and the rest left out.</summary>
    private static List<int> CapturedGroups(string captured)
    {
        return captured.Chunk(4)
            .Select(chunk => Convert.ToInt32(new string(chunk), 16))
            .Where(GroupIds.ContainsValue)
            .ToList();
    }

    private static List<int> GroupsOf(AetherFingerprint fingerprint)
    {
        return fingerprint.Groups.Split(':').Select(name => GroupIds[name]).ToList();
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
        // Chrome 120's, baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035, comes from the same rule: the same suites in the
        // same order.
        await AetherFingerprint.Chrome120.Ciphers.Should().BeEqualTo(AetherFingerprint.Chrome.Ciphers);
        await Tls12Of("baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035")
            .SequenceEqual(Tls12Of("eaea130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035"))
            .Should().BeTrue();
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

    // From PattNG AetherKeysTest.
    [Test]
    public async Task EachFingerprintOffersTheGroupsOfItsCapturedClientHelloThatBoringSslHas()
    {
        // The supported_groups of the ClientHellos captured in October 2026. Chrome's and Chrome 120's lead with a GREASE
        // value, and Chrome 120's has no post-quantum group; Python's
        // also lists X448, ffdhe2048 and ffdhe3072, and Go's SecP256r1MLKEM768 and SecP384r1MLKEM1024, none of which
        // BoringSSL has.
        await GroupsOf(AetherFingerprint.Chrome).SequenceEqual(CapturedGroups("5a5a11ec001d00170018")).Should().BeTrue();
        await GroupsOf(AetherFingerprint.Chrome120).SequenceEqual(CapturedGroups("5a5a001d00170018")).Should().BeTrue();
        await GroupsOf(AetherFingerprint.Firefox).SequenceEqual(CapturedGroups("11ec001d001700180019")).Should().BeTrue();
        await GroupsOf(AetherFingerprint.SemiPython).SequenceEqual(CapturedGroups("11ec001d0017001e0018001901000101")).Should().BeTrue();
        await GroupsOf(AetherFingerprint.Go).SequenceEqual(CapturedGroups("11ec11eb11ed001d001700180019")).Should().BeTrue();
    }

    // From PattNG AetherKeysTest.
    [Test]
    public async Task EachFingerprintOffersTheTls13OrderAndTheKeySharesOfItsCapturedClientHello()
    {
        // Firefox and Python list their TLS 1.3 suites in an order of their own, which their fingerprints name.
        static List<int> Named(string? list) => list!.Split(':').Select(name => Tls13Ids[name]).ToList();
        await Named(AetherFingerprint.Firefox.Tls13Ciphers)
            .SequenceEqual(Tls13Of("130113031302c02bc02fcca9cca8c02cc030c013c014009c009d002f0035"))
            .Should().BeTrue();
        await Named(AetherFingerprint.SemiPython.Tls13Ciphers)
            .SequenceEqual(Tls13Of("130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b0067"))
            .Should().BeTrue();
        // Chrome's and Go's are BoringSSL's own order, by the machine's AES instructions, as their captures on a PC with
        // them show; a fixed list would keep AES-GCM first where they go ChaCha20 first.
        await Tls13Of("eaea130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035").SequenceEqual([0x1301, 0x1302, 0x1303]).Should().BeTrue();
        await Tls13Of("c02bc02fc02cc030cca9cca8c009c013c00ac014130113021303").SequenceEqual([0x1301, 0x1302, 0x1303]).Should().BeTrue();
        await Tls13Of("baba130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035").SequenceEqual([0x1301, 0x1302, 0x1303]).Should().BeTrue();
        await AetherFingerprint.Chrome.Tls13Ciphers.Should().BeNull();
        await AetherFingerprint.Chrome120.Tls13Ciphers.Should().BeNull();
        await AetherFingerprint.Go.Tls13Ciphers.Should().BeNull();

        // Firefox's key_share carries X25519MLKEM768, X25519 and P-256; the others carry the two BoringSSL sends, the
        // first group and the first that is not post-quantum.
        await AetherFingerprint.Firefox.KeyShares!.Split(':').Select(name => GroupIds[name]).SequenceEqual([0x11ec, 0x001d, 0x0017]).Should().BeTrue();
        foreach (var fingerprint in new[] { AetherFingerprint.Chrome, AetherFingerprint.Chrome120, AetherFingerprint.SemiPython, AetherFingerprint.Go })
        {
            await fingerprint.KeyShares.Should().BeNull();
        }
    }

    // From PattNG AetherKeysTest; the check of AetherKeys.arguments for every fingerprint goes with AetherKeys.
    [Test]
    public async Task OnlyChromeSendsGrease()
    {
        await AetherFingerprint.Chrome.Grease.Should().BeTrue();
        await AetherFingerprint.Chrome120.Grease.Should().BeTrue();
        await AetherFingerprint.Firefox.Grease.Should().BeFalse();
        await AetherFingerprint.SemiPython.Grease.Should().BeFalse();
        await AetherFingerprint.Go.Grease.Should().BeFalse();
        // Chrome of today alone sends one among its signature algorithms as well; Chrome 120 did not.
        await AetherFingerprint.All.Where(it => it.GreaseSigalgs).SequenceEqual([AetherFingerprint.Chrome]).Should().BeTrue();
    }

    // From PattNG AetherKeysTest.
    [Test]
    public async Task EachFingerprintNamesItsSuitesAndItsGroups()
    {
        // Each is named, so that the core's defaults cannot change it. GREASE is the one left to the core, which has no
        // option that turns it on; Chrome alone keeps it. The TLS 1.3 order and the key shares are named where they are
        // not BoringSSL's.
        const string groups = "X25519MLKEM768:X25519:P-256:P-384:P-521";
        await AetherFingerprint.Chrome.Arguments
            .SequenceEqual([
                "--tls-ciphers", "ALL:!aPSK:!ECDSA+SHA1:!3DES",
                "--tls-groups", "X25519MLKEM768:X25519:P-256:P-384",
                "--enable-grease-sigalgs",
            ])
            .Should().BeTrue();
        await AetherFingerprint.Chrome120.Arguments
            .SequenceEqual(["--tls-ciphers", "ALL:!aPSK:!ECDSA+SHA1:!3DES", "--tls-groups", "X25519:P-256:P-384"])
            .Should().BeTrue();
        await AetherFingerprint.Firefox.Arguments
            .SequenceEqual([
                "--tls-ciphers", AetherFingerprint.Firefox.Ciphers,
                "--tls13-ciphers", "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
                "--tls-groups", groups,
                "--tls-key-shares", "X25519MLKEM768:X25519:P-256",
                "--disable-grease",
            ])
            .Should().BeTrue();
        await AetherFingerprint.SemiPython.Arguments
            .SequenceEqual([
                "--tls-ciphers", AetherFingerprint.SemiPython.Ciphers,
                "--tls13-ciphers", "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256",
                "--tls-groups", groups,
                "--disable-grease",
            ])
            .Should().BeTrue();
        await AetherFingerprint.Go.Arguments
            .SequenceEqual(["--tls-ciphers", AetherFingerprint.Go.Ciphers, "--tls-groups", groups, "--disable-grease"])
            .Should().BeTrue();
    }

    // From PattNG AetherKeysTest. Its check of the dropdown's labels (Chrome, Firefox, Semi-Python, Go) against this
    // order goes with the editor and the WARP keys window, which list them by their index in All.
    [Test]
    public async Task TheFingerprintListNamesEveryFingerprintInItsOrder()
    {
        await AetherFingerprint.All.Select(it => it.Type).SequenceEqual(["chrome", "chrome-120", "firefox", "semi-python", "go"]).Should().BeTrue();
        await AetherFingerprint.FromString("semi-python").Should().BeEqualTo(AetherFingerprint.SemiPython);
    }
}
