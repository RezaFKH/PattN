namespace ServiceLib.Tests.Common;

/// <summary>
/// From PattNG TlsSettingsCheckTest, its cipherSuites rule: cipherSuites the Xray-core fork would not apply, which the
/// editor refuses to save. PattN fills an empty fingerprint with the default of its settings, which the check is given.
/// </summary>
public class TlsSettingsCheckTests
{
    private const string Suites = "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";

    private static ProfileItem Profile(
        string? fingerprint = null,
        string? cipherSuites = null,
        EConfigType type = EConfigType.VLESS,
        string security = Global.StreamSecurity)
    {
        return new ProfileItem
        {
            ConfigType = type,
            StreamSecurity = security,
            Fingerprint = fingerprint ?? string.Empty,
            CipherSuites = cipherSuites ?? string.Empty,
            Network = "ws",
        };
    }

    // PattNG: an empty fingerprint is Chrome's; PattN's default fingerprint stands in for it, Chrome's here.
    private static bool NeedUnsafe(ProfileItem profile, string? defaultFingerprint = "chrome")
    {
        return TlsSettingsCheck.CipherSuitesNeedUnsafe(profile, defaultFingerprint);
    }

    [Test]
    public async Task CipherSuitesNeedTheUnsafeFingerprint()
    {
        await NeedUnsafe(Profile(fingerprint: "unsafe", cipherSuites: Suites)).Should().BeFalse();
        // The fork lowercases the fingerprint.
        await NeedUnsafe(Profile(fingerprint: "Unsafe", cipherSuites: Suites)).Should().BeFalse();
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: Suites)).Should().BeTrue();
        // An empty fingerprint is the default one.
        await NeedUnsafe(Profile(fingerprint: "", cipherSuites: Suites)).Should().BeTrue();
        await NeedUnsafe(Profile(fingerprint: "randomized", cipherSuites: Suites)).Should().BeTrue();
        // No cipherSuites, nothing to refuse.
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: "")).Should().BeFalse();
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: " \n")).Should().BeFalse();
        await NeedUnsafe(Profile(fingerprint: "chrome")).Should().BeFalse();
    }

    [Test]
    public async Task TheCheckKeepsToTheEditorsThatShowTheseSettingsUnderTls()
    {
        foreach (var type in new[] { EConfigType.VMess, EConfigType.VLESS, EConfigType.Shadowsocks, EConfigType.Trojan })
        {
            await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: Suites, type: type)).Should().BeTrue().Because(type.ToString());
        }
        // Hysteria2's editor shows no cipherSuites, so a value an imported link left there is not refused.
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: Suites, type: EConfigType.Hysteria2)).Should().BeFalse();
        // Nor under REALITY or without security, where the editor hides them.
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: Suites, security: Global.StreamSecurityReality)).Should().BeFalse();
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: Suites, security: "")).Should().BeFalse();
    }

    // PattN: an empty fingerprint is the one the settings give Xray in its place.
    [Test]
    public async Task AnEmptyFingerprintIsTheDefaultOneOfTheSettings()
    {
        await NeedUnsafe(Profile(cipherSuites: Suites), defaultFingerprint: "unsafe").Should().BeFalse();
        await NeedUnsafe(Profile(cipherSuites: Suites), defaultFingerprint: "UNSAFE").Should().BeFalse();
        await NeedUnsafe(Profile(cipherSuites: Suites), defaultFingerprint: "chrome").Should().BeTrue();
        // With no default either, the fork takes its own, which is not unsafe.
        await NeedUnsafe(Profile(cipherSuites: Suites), defaultFingerprint: "").Should().BeTrue();
        await NeedUnsafe(Profile(cipherSuites: Suites), defaultFingerprint: null).Should().BeTrue();
        // A fingerprint of the profile's own goes before the default.
        await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: Suites), defaultFingerprint: "unsafe").Should().BeTrue();
        await NeedUnsafe(Profile(fingerprint: "unsafe", cipherSuites: Suites), defaultFingerprint: "chrome").Should().BeFalse();
    }

    // PattN: the presets of the cipherSuites field are what the rule is for.
    [Test]
    public async Task EveryCipherSuitesPresetNeedsTheUnsafeFingerprint()
    {
        foreach (var (name, value) in Global.CipherSuitesPresets)
        {
            await NeedUnsafe(Profile(fingerprint: "chrome", cipherSuites: value)).Should().BeTrue().Because(name);
            await NeedUnsafe(Profile(fingerprint: "unsafe", cipherSuites: value)).Should().BeFalse().Because(name);
        }
    }
}
