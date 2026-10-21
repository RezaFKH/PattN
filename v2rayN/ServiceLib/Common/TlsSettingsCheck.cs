namespace ServiceLib.Common;

// PattN: fork-only file, the cipherSuites rule of PattNG core/TlsSettingsCheck.kt.

/// <summary>
/// PattN: TLS settings of a profile that the patterniha Xray-core fork would not apply, so that the editor does not save
/// them (PattNG core/TlsSettingsCheck.kt, its cipherSuites rule; read from the fork's transport/internet/tls). The fork
/// builds the ClientHello with uTLS for every fingerprint but unsafe and passes uTLS no cipher suites, so cipherSuites
/// apply with the unsafe fingerprint alone.
/// </summary>
public static class TlsSettingsCheck
{
    /// <summary>The fingerprint with which the fork builds the ClientHello with Go's crypto/tls rather than with uTLS.</summary>
    public const string UnsafeFingerprint = "unsafe";

    /// <summary>
    /// Whether the check applies to <paramref name="profile" />, which is where the editor shows cipherSuites and the
    /// fingerprint: under TLS on VMess, VLESS, Shadowsocks and Trojan.
    /// </summary>
    public static bool AppliesTo(ProfileItem profile)
    {
        return profile.ConfigType is EConfigType.VMess or EConfigType.VLESS or EConfigType.Shadowsocks or EConfigType.Trojan
               && profile.StreamSecurity == Global.StreamSecurity;
    }

    /// <summary>
    /// Whether <paramref name="profile" /> holds cipherSuites the fork would not apply: cipherSuites that are not blank,
    /// with a fingerprint other than unsafe, which the fork lowercases before it looks it up. PattN gives Xray
    /// <paramref name="defaultFingerprint" />, the default of the settings (CoreBasicItem.DefFingerprint), in place of an
    /// empty fingerprint, where PattNG gives Chrome's; an empty one there as well is the fork's own, which is not unsafe.
    /// False where the check does not apply.
    /// </summary>
    public static bool CipherSuitesNeedUnsafe(ProfileItem profile, string? defaultFingerprint)
    {
        if (!AppliesTo(profile) || KotlinText.IsBlank(profile.CipherSuites))
        {
            return false;
        }
        var fingerprint = string.IsNullOrEmpty(profile.Fingerprint) ? defaultFingerprint : profile.Fingerprint;
        return fingerprint?.ToLowerInvariant() != UnsafeFingerprint;
    }
}
