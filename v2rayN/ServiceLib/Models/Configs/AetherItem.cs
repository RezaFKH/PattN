namespace ServiceLib.Models.Configs;

/// <summary>
/// PattN: the settings of Aether that belong to no profile (PattNG's PREF_PSIPHON_REGIONS and, later, the settings of the
/// WARP keys window). They live in guiNConfig.json and go into backups; the WARP keys themselves do not.
/// </summary>
[Serializable]
public class AetherItem
{
    /// <summary>
    /// Psiphon's last report of the countries it can leave from, sorted and comma-joined, for the exit country list of
    /// the Aether editor (PattNG PsiphonServerList.remember); null or empty before the first report.
    /// </summary>
    public string? PsiphonRegions { get; set; }
}
