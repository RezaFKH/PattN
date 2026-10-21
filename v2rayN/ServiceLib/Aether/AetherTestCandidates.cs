namespace ServiceLib.Aether;

/// <summary>
/// PattN (design 2.12.1, critique 25): which profiles of one run of tests need an Aether core, and so leave the batch, in
/// which one Xray serves many profiles, for <see cref="AetherDelayTester" />, which tests them one at a time: an Aether
/// profile, a policy group or a proxy chain with one among its members, at whatever depth, and a profile whose
/// subscription chains it with one, as its previous or its next profile (CoreConfigContextBuilder wraps every profile of
/// such a subscription). It is told from the stored profiles, without building a configuration for each: the previous and
/// next profiles of a subscription are looked up once per subscription and run. The test of each such profile builds its
/// configuration all the same, which has the last word. Only a profile another core runs is built here, see
/// <see cref="TakeAsync" />.
/// </summary>
/// <param name="refused">
/// Whether the checks a session start makes refuse a profile (CoreConfigContextBuilder.Build); null leaves every profile
/// another core than Xray runs to the batch.
/// </param>
public sealed class AetherTestCandidates(
    Func<string, Task<SubItem?>> subscription,
    Func<string, Task<ProfileItem?>> profileNamed,
    Func<ProfileItem, Task<IEnumerable<ProfileItem>>> members,
    Func<ProfileItem, Task<bool>>? refused = null)
{
    private readonly Dictionary<string, bool> _subscriptions = new(StringComparer.Ordinal);
    private readonly Dictionary<string, bool> _names = new(StringComparer.Ordinal);

    /// <summary>The candidates of PattN's own database.</summary>
    public static AetherTestCandidates FromDatabase()
    {
        return new AetherTestCandidates(
            subId => AppManager.Instance.GetSubItem(subId),
            name => AppManager.Instance.GetProfileItemViaRemarks(name),
            async group => (await GroupProfileManager.GetAllChildProfileItems(group)).Values,
            async profile => !(await CoreConfigContextBuilder.Build(AppManager.Instance.Config, profile)).ValidatorResult.Success);
    }

    /// <summary>
    /// Takes the items that need an Aether core out of <paramref name="items" />, and returns them in their order: those of
    /// <see cref="NeedsAetherAsync" /> that Xray runs, or, for a TCP ping, which opens no tunnel, the Aether profiles
    /// alone, whose edge it probes (a group or a chain keeps PattN's TCP ping). A profile another core runs, which runs no
    /// Aether profile, leaves only when the checks a session start makes refuse it: a chain with an Aether hop is built
    /// whole or not at all (critique 4), and the test of a single profile of that core, which skips the checks, would
    /// measure it the shorter way, without the hop; the tester refuses it (-1) as its session is refused. A group of that
    /// core, which leaves its Aether member out as its session does, stays. The others stay, in their order, for the batch.
    /// </summary>
    public async Task<List<ServerTestItem>> TakeAsync(ESpeedActionType actionType, List<ServerTestItem> items)
    {
        var taken = new List<ServerTestItem>();
        foreach (var item in items)
        {
            if (actionType == ESpeedActionType.Tcping
                    ? item.ConfigType == EConfigType.Aether
                    : await LeavesTheBatchAsync(item))
            {
                taken.Add(item);
            }
        }
        if (taken.Count > 0)
        {
            var leaving = new HashSet<ServerTestItem>(taken, ReferenceEqualityComparer.Instance);
            items.RemoveAll(leaving.Contains);
        }
        return taken;
    }

    /// <summary>
    /// Whether <paramref name="profile" /> needs an Aether core: it is an Aether profile, a group or a chain with one among
    /// its members, or its subscription chains it with one.
    /// </summary>
    public async Task<bool> NeedsAetherAsync(ProfileItem profile)
    {
        if (await HoldsAetherAsync(profile).ConfigureAwait(false))
        {
            return true;
        }
        if (profile.Subid.IsNullOrEmpty() || profile.ConfigType == EConfigType.Custom)
        {
            return false;
        }
        if (!_subscriptions.TryGetValue(profile.Subid, out var chained))
        {
            chained = await ChainsAetherAsync(profile.Subid).ConfigureAwait(false);
            _subscriptions[profile.Subid] = chained;
        }
        return chained;
    }

    /// <summary>Whether a latency or speed test of <paramref name="item" /> is the Aether tester's, see <see cref="TakeAsync" />.</summary>
    private async Task<bool> LeavesTheBatchAsync(ServerTestItem item)
    {
        var xray = item.CoreType == ECoreType.Xray;
        if (!xray && refused == null)
        {
            return false;
        }
        var profile = item.Profile ?? new ProfileItem { ConfigType = item.ConfigType };
        if (!await NeedsAetherAsync(profile).ConfigureAwait(false))
        {
            return false;
        }
        return xray || await refused!(profile).ConfigureAwait(false);
    }

    /// <summary>Whether <paramref name="profile" /> is an Aether profile, or a group or a chain with one among its members.</summary>
    private async Task<bool> HoldsAetherAsync(ProfileItem profile)
    {
        if (profile.ConfigType == EConfigType.Aether)
        {
            return true;
        }
        if (!profile.ConfigType.IsGroupType())
        {
            return false;
        }
        return (await members(profile).ConfigureAwait(false)).Any(member => member.ConfigType == EConfigType.Aether);
    }

    /// <summary>Whether the subscription <paramref name="subId" /> chains its profiles with a previous or a next one that holds Aether.</summary>
    private async Task<bool> ChainsAetherAsync(string subId)
    {
        var sub = await subscription(subId).ConfigureAwait(false);
        if (sub == null)
        {
            return false;
        }
        foreach (var name in new[] { sub.PrevProfile, sub.NextProfile })
        {
            if (name.IsNullOrEmpty())
            {
                continue;
            }
            if (!_names.TryGetValue(name, out var holds))
            {
                holds = await profileNamed(name).ConfigureAwait(false) is { } named && await HoldsAetherAsync(named).ConfigureAwait(false);
                _names[name] = holds;
            }
            if (holds)
            {
                return true;
            }
        }
        return false;
    }
}
