using ServiceLib.Tests.CoreConfig;
using TUnit.Assertions.Enums;

namespace ServiceLib.Tests.Aether;

/// <summary>
/// PattN (design 2.12.1, critique 25): which profiles of a test run need an Aether core and leave the batch, told from the
/// stored profiles, the subscriptions resolved once each.
/// </summary>
public class AetherTestCandidatesTests
{
    private static ProfileItem Warp(string id = "warp", string? subId = null)
    {
        var profile = CoreConfigTestFactory.CreateAetherNode(id, $"WARP {id}");
        profile.Subid = subId ?? string.Empty;
        return profile;
    }

    private static ProfileItem Vless(string id, string? subId = null)
    {
        return new ProfileItem
        {
            IndexId = id,
            ConfigType = EConfigType.VLESS,
            CoreType = ECoreType.Xray,
            Remarks = id,
            Address = "203.0.113.7",
            Port = 443,
            Subid = subId ?? string.Empty,
        };
    }

    /// <summary>The candidates of a store of <paramref name="subscriptions" />, <paramref name="profiles" /> by name and group members, counting the lookups.</summary>
    private sealed class Store
    {
        public Dictionary<string, SubItem> Subscriptions { get; } = [];
        public Dictionary<string, ProfileItem> ByName { get; } = [];
        public Dictionary<string, List<ProfileItem>> Members { get; } = [];
        public List<string> Lookups { get; } = [];

        /// <summary>The profiles the checks of a session start refuse, by id; null to leave out the checks.</summary>
        public HashSet<string>? Refused { get; set; }

        public AetherTestCandidates Candidates()
        {
            return new AetherTestCandidates(
                subId =>
                {
                    Lookups.Add($"sub {subId}");
                    return Task.FromResult(Subscriptions.GetValueOrDefault(subId));
                },
                name =>
                {
                    Lookups.Add($"name {name}");
                    return Task.FromResult(ByName.GetValueOrDefault(name));
                },
                group =>
                {
                    Lookups.Add($"members {group.IndexId}");
                    return Task.FromResult<IEnumerable<ProfileItem>>(Members.GetValueOrDefault(group.IndexId) ?? []);
                },
                Refused is { } refused
                    ? profile =>
                    {
                        Lookups.Add($"checks {profile.IndexId}");
                        return Task.FromResult(refused.Contains(profile.IndexId));
                    }
                    : null);
        }
    }

    [Test]
    public async Task AnAetherProfileNeedsItsCore()
    {
        var store = new Store();
        await (await store.Candidates().NeedsAetherAsync(Warp())).Should().BeTrue();
        await (await store.Candidates().NeedsAetherAsync(Vless("v"))).Should().BeFalse();
        // Neither asks the store: no subscription, no members.
        await store.Lookups.Should().BeEmpty();
    }

    [Test]
    public async Task AGroupOrAChainWithAnAetherMemberNeedsItsCore()
    {
        var store = new Store();
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, "group", "group", ["v", "warp"]);
        store.Members["group"] = [Vless("v"), Warp()];
        var chain = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, "chain", "chain", ["v", "w"]);
        store.Members["chain"] = [Vless("v"), Vless("w")];

        await (await store.Candidates().NeedsAetherAsync(group)).Should().BeTrue();
        await (await store.Candidates().NeedsAetherAsync(chain)).Should().BeFalse();
    }

    [Test]
    public async Task AProfileItsSubscriptionChainsWithAnAetherProfileNeedsItsCore()
    {
        var store = new Store();
        store.Subscriptions["sub"] = new SubItem { Id = "sub", Remarks = "sub", PrevProfile = "WARP prev" };
        store.ByName["WARP prev"] = Warp("prev");
        store.Subscriptions["plain"] = new SubItem { Id = "plain", Remarks = "plain", NextProfile = "exit" };
        store.ByName["exit"] = Vless("exit");
        // The next profile a group holding Aether.
        store.Subscriptions["grouped"] = new SubItem { Id = "grouped", Remarks = "grouped", NextProfile = "pool" };
        store.ByName["pool"] = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, "pool", "pool", ["prev"]);
        store.Members["pool"] = [Warp("prev")];
        var candidates = store.Candidates();

        await (await candidates.NeedsAetherAsync(Vless("a", "sub"))).Should().BeTrue();
        await (await candidates.NeedsAetherAsync(Vless("b", "plain"))).Should().BeFalse();
        await (await candidates.NeedsAetherAsync(Vless("c", "grouped"))).Should().BeTrue();
        await (await candidates.NeedsAetherAsync(Vless("d", "missing"))).Should().BeFalse();
    }

    [Test]
    public async Task ASubscriptionIsResolvedOncePerRun()
    {
        var store = new Store();
        store.Subscriptions["sub"] = new SubItem { Id = "sub", Remarks = "sub", PrevProfile = "WARP prev", NextProfile = "exit" };
        store.ByName["WARP prev"] = Vless("not aether");
        store.ByName["exit"] = Vless("exit");
        var candidates = store.Candidates();

        foreach (var id in new[] { "a", "b", "c", "d" })
        {
            await (await candidates.NeedsAetherAsync(Vless(id, "sub"))).Should().BeFalse();
        }

        // Every profile of the subscription is chained the same way: one lookup of it and of each name, not one per profile.
        await store.Lookups.Should().BeEquivalentTo(["sub sub", "name WARP prev", "name exit"], CollectionOrdering.Matching);
    }

    private static ServerTestItem Item(ProfileItem profile, ECoreType coreType = ECoreType.Xray)
    {
        return new ServerTestItem
        {
            IndexId = profile.IndexId,
            ConfigType = profile.ConfigType,
            Port = profile.Port,
            Profile = profile,
            CoreType = coreType,
        };
    }

    [Test]
    public async Task ThePartitionKeepsTheBatchForTheRest()
    {
        var store = new Store();
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, "group", "group", ["warp"]);
        store.Members["group"] = [Warp()];
        var singBoxGroup = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.sing_box, "sb-group", "sb-group", ["warp"]);
        store.Members["sb-group"] = [Warp()];
        var v1 = Item(Vless("v1"));
        var warp = Item(Warp());
        var v2 = Item(Vless("v2"));
        var grouped = Item(group);
        var singBox = Item(singBoxGroup, ECoreType.sing_box);
        var v3 = Item(Vless("v3"));
        var batch = new List<ServerTestItem> { v1, warp, v2, grouped, singBox, v3 };

        var taken = await store.Candidates().TakeAsync(ESpeedActionType.Realping, batch);

        // The Aether profile and the Xray group holding one leave, in their order; the rest stays for the batch, in its
        // order, sing-box's group with it (sing-box runs no Aether profile: its checks leave it out).
        await taken.Should().BeEquivalentTo([warp, grouped], CollectionOrdering.Matching);
        await batch.Should().BeEquivalentTo([v1, v2, singBox, v3], CollectionOrdering.Matching);
    }

    [Test]
    public async Task AProfileAnotherCoreRunsLeavesTheBatchOnlyWhenItsSessionWouldBeRefused()
    {
        // Critique 4: sing-box runs no Aether profile, so a chain of it with an Aether hop is refused whole; the test of one
        // profile of sing-box skips those checks and would measure the chain the shorter way, without the hop. It goes to
        // the Aether tester, which refuses it (-1) as its session is refused. A group of sing-box with an Aether member
        // runs without it, as its session does, and keeps its batch test.
        var store = new Store { Refused = ["sb-chain", "sb-sub"] };
        var chain = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.sing_box, "sb-chain", "sb-chain", ["v", "warp"]);
        store.Members["sb-chain"] = [Vless("v"), Warp()];
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.sing_box, "sb-group", "sb-group", ["v", "warp"]);
        store.Members["sb-group"] = [Vless("v"), Warp()];
        store.Subscriptions["sub"] = new SubItem { Id = "sub", Remarks = "sub", PrevProfile = "WARP" };
        store.ByName["WARP"] = Warp();
        var subscribed = Vless("sb-sub", "sub");
        var plain = Vless("sb-plain");
        var chained = Item(chain, ECoreType.sing_box);
        var grouped = Item(group, ECoreType.sing_box);
        var wrapped = Item(subscribed, ECoreType.sing_box);
        var alone = Item(plain, ECoreType.sing_box);
        var batch = new List<ServerTestItem> { chained, grouped, wrapped, alone };

        foreach (var actionType in new[] { ESpeedActionType.Realping, ESpeedActionType.Speedtest, ESpeedActionType.Mixedtest })
        {
            var items = new List<ServerTestItem>(batch);
            var taken = await store.Candidates().TakeAsync(actionType, items);

            await taken.Should().BeEquivalentTo([chained, wrapped], CollectionOrdering.Matching).Because(actionType.ToString());
            await items.Should().BeEquivalentTo([grouped, alone], CollectionOrdering.Matching).Because(actionType.ToString());
        }
        // Only a profile that needs an Aether core is built for its checks.
        await store.Lookups.Contains("checks sb-plain").Should().BeFalse();
        // Without the checks, a profile of another core stays, and nothing is looked up for it.
        var withoutChecks = new Store();
        withoutChecks.Members["sb-chain"] = [Vless("v"), Warp()];
        var left = new List<ServerTestItem> { chained };
        await (await withoutChecks.Candidates().TakeAsync(ESpeedActionType.Realping, left)).Should().BeEmpty();
        await withoutChecks.Lookups.Should().BeEmpty();
    }

    [Test]
    public async Task ATcpPingTakesOnlyTheAetherProfiles()
    {
        // A TCP ping opens no tunnel: an Aether profile's edge is probed, and a group keeps PattN's TCP ping.
        var store = new Store();
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, "group", "group", ["warp"]);
        store.Members["group"] = [Warp()];
        var warp = Item(Warp());
        var grouped = Item(group);
        var chained = Item(Vless("v", "sub"));
        store.Subscriptions["sub"] = new SubItem { Id = "sub", Remarks = "sub", PrevProfile = "WARP" };
        store.ByName["WARP"] = Warp();
        var batch = new List<ServerTestItem> { grouped, warp, chained };

        var taken = await store.Candidates().TakeAsync(ESpeedActionType.Tcping, batch);

        await taken.Should().BeEquivalentTo([warp], CollectionOrdering.Matching);
        await batch.Should().BeEquivalentTo([grouped, chained], CollectionOrdering.Matching);
        await store.Lookups.Should().BeEmpty();
    }
}
