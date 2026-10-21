using static ServiceLib.Tests.CoreConfig.V2ray.AetherConfigTests;

namespace ServiceLib.Tests.CoreConfig.Context;

/// <summary>
/// PattN (PattNG CoreConfigContextBuilder.kt resolveOutbound): the profile a routing rule sends to runs inside its
/// subscription's previous/next chain, as the main profile does, whatever its type; upstream v2rayN resolves it alone.
/// The chain is stored entry hop first (previous, profile, next), and built from the exit hop, which the rule sends to.
/// Each test builds the whole context (CoreConfigContextBuilder.Build) with a routing of its own made the active one in
/// the test database, and gives the active one back after; every name is new to the test, as the database is shared.
/// </summary>
[NotInParallel]
public class RuleTargetChainTests
{
    private const string RuleName = "rule to a subscription profile";
    private const string RuleDomain = "rule.example.com";

    private static string NewName(string prefix)
    {
        return $"{prefix}-{Guid.NewGuid():N}";
    }

    private static async Task Store(params ProfileItem[] profiles)
    {
        SQLiteHelper.Instance.CreateTable<ProfileItem>();
        foreach (var profile in profiles)
        {
            await SQLiteHelper.Instance.ReplaceAsync(profile);
        }
    }

    /// <summary>A stored subscription with the previous and the next profile it names; its id.</summary>
    private static async Task<string> Subscription(string? prev, string? next)
    {
        SQLiteHelper.Instance.CreateTable<SubItem>();
        var id = NewName("sub");
        await SQLiteHelper.Instance.ReplaceAsync(new SubItem { Id = id, Remarks = "chained", Url = string.Empty, PrevProfile = prev, NextProfile = next });
        return id;
    }

    private static ProfileItem In(string subId, ProfileItem profile)
    {
        profile.Subid = subId;
        return profile;
    }

    /// <summary>The hops of a subscription's chain around <paramref name="profile" />, entry first, as it is stored.</summary>
    private static ProfileItem[] Hops(ProfileItem? prev, ProfileItem profile, ProfileItem? next)
    {
        return new[] { prev, profile, next }.OfType<ProfileItem>().ToArray();
    }

    private static ProfileItem XrayHop(string prefix, string address)
    {
        return Vless(NewName(prefix), NewName(prefix), address);
    }

    private static ProfileItem SingboxHop(string prefix, string address)
    {
        var hop = CoreConfigTestFactory.CreateSocksNode(ECoreType.sing_box, NewName(prefix), NewName(prefix));
        hop.Address = address;
        return hop;
    }

    /// <summary>A TUIC profile, which Xray cannot run.</summary>
    private static ProfileItem TuicHop(string prefix, string address)
    {
        return new ProfileItem
        {
            IndexId = NewName(prefix),
            ConfigType = EConfigType.TUIC,
            CoreType = ECoreType.sing_box,
            Remarks = NewName(prefix),
            Address = address,
            Port = 443,
            Username = Guid.NewGuid().ToString(),
            Password = "pass",
            Network = nameof(ETransport.raw),
            StreamSecurity = Global.StreamSecurity,
            Subid = string.Empty,
        };
    }

    /// <summary>A VLESS profile over xhttp, which sing-box cannot run.</summary>
    private static ProfileItem XhttpHop(string prefix, string address)
    {
        var hop = XrayHop(prefix, address);
        hop.Network = nameof(ETransport.xhttp);
        return hop;
    }

    /// <summary>The warning of a rule that goes to the proxy because the chain of its subscription lost <paramref name="lost" />.</summary>
    private static string ChainLost(ProfileItem target, ProfileItem lost)
    {
        return string.Format(ResUI.MsgRoutingRuleOutboundNodeError, RuleName, target.Remarks,
            string.Format(ResUI.MsgRoutingRuleChainHopNotBuilt, lost.Remarks));
    }

    /// <summary>Nothing of <paramref name="profiles" />, nor a chain of a subscription, stayed in the context.</summary>
    private static async Task AssertNoneRegistered(CoreConfigContext context, params ProfileItem[] profiles)
    {
        foreach (var profile in profiles)
        {
            await context.AllProxiesMap.Should().NotContainKey(profile.IndexId);
        }
        await context.AllProxiesMap.Keys.Any(key => key.StartsWith("inner-", StringComparison.Ordinal)).Should().BeFalse();
    }

    /// <summary>
    /// The context Build makes for <paramref name="main" /> while the active routing has one rule, sending
    /// <see cref="RuleDomain" /> to the profile named <paramref name="target" />.
    /// </summary>
    private static Task<CoreConfigContextBuilderResult> BuildWithRuleTo(Config config, ProfileItem main, string target)
    {
        return WithRuleTo(target, () => CoreConfigContextBuilder.Build(config, main));
    }

    /// <summary>What <paramref name="build" /> gives while the active routing has one rule, sending <see cref="RuleDomain" /> to <paramref name="target" />.</summary>
    private static async Task<T> WithRuleTo<T>(string target, Func<Task<T>> build)
    {
        SQLiteHelper.Instance.CreateTable<FullConfigTemplateItem>();
        SQLiteHelper.Instance.CreateTable<DNSItem>();
        SQLiteHelper.Instance.CreateTable<RoutingItem>();
        var wasActive = (await AppManager.Instance.RoutingItems() ?? []).Where(routing => routing.IsActive).ToList();
        var routing = new RoutingItem
        {
            Id = NewName("routing"),
            Remarks = "rule targets",
            RuleSet = JsonUtils.Serialize(new List<RulesItem>
            {
                new()
                {
                    Id = NewName("rule"),
                    Remarks = RuleName,
                    Enabled = true,
                    RuleType = ERuleType.Routing,
                    OutboundTag = target,
                    Domain = [$"full:{RuleDomain}"],
                },
            }),
            DomainStrategy = Global.AsIs,
            DomainStrategy4Singbox = string.Empty,
            IsActive = true,
        };
        wasActive.ForEach(other => other.IsActive = false);
        await SQLiteHelper.Instance.UpdateAllAsync(wasActive);
        await SQLiteHelper.Instance.ReplaceAsync(routing);
        try
        {
            return await build();
        }
        finally
        {
            await SQLiteHelper.Instance.DeleteAsync(routing);
            wasActive.ForEach(other => other.IsActive = true);
            await SQLiteHelper.Instance.UpdateAllAsync(wasActive);
        }
    }

    private static async Task<CoreConfigContext> Built(Config config, ProfileItem main, string target)
    {
        var (context, result) = await BuildWithRuleTo(config, main, target);
        await result.Success.Should().BeTrue().Because(string.Join(" | ", result.Errors));
        return context;
    }

    /// <summary>The profile the rule to <paramref name="target" /> resolved to, as the routing services read it.</summary>
    private static ProfileItem? RuleNode(CoreConfigContext context, ProfileItem target)
    {
        return context.AllProxiesMap.GetValueOrDefault($"remark:{target.Remarks}");
    }

    private static string RuleTag(ProfileItem ruleNode)
    {
        return $"{ruleNode.IndexId}-{Global.ProxyTag}-{ruleNode.Remarks}";
    }

    /// <summary>The rule's node is the chain of <paramref name="storedEntryFirst" />, in their order.</summary>
    private static async Task<ProfileItem> AssertChain(CoreConfigContext context, ProfileItem target, params ProfileItem[] storedEntryFirst)
    {
        var chain = RuleNode(context, target);
        await (chain?.ConfigType).Should().BeEqualTo(EConfigType.ProxyChain);
        await chain!.Remarks.Should().BeEqualTo(target.Remarks);
        await chain.GetProtocolExtra().ChildItems.Should().BeEqualTo(string.Join(",", storedEntryFirst.Select(hop => hop.IndexId)));
        return chain;
    }

    private static string HopTag(string tag, List<ProfileItem> exitFirst, int i)
    {
        return i == 0 ? tag : $"chain-{tag}-{i}-{exitFirst[i].Remarks}";
    }

    /// <summary>Xray dials the rule's chain from its exit hop, tagged as the rule's outbound, to its entry hop.</summary>
    private static async Task AssertXrayChain(CoreConfigContext context, ProfileItem chain, params ProfileItem[] storedEntryFirst)
    {
        var generated = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        await generated.Success.Should().BeTrue().Because(generated.Msg ?? string.Empty);
        var config = JsonUtils.Deserialize<V2rayConfig>(generated.Data!.ToString())!;
        var tag = RuleTag(chain);
        var exitFirst = storedEntryFirst.AsEnumerable().Reverse().ToList();
        for (var i = 0; i < exitFirst.Count; i++)
        {
            var outbound = config.outbounds.Single(outbound => outbound.tag == HopTag(tag, exitFirst, i));
            await outbound.settings.address!.ToString().Should().BeEqualTo(exitFirst[i].Address);
            var dialer = i + 1 < exitFirst.Count ? HopTag(tag, exitFirst, i + 1) : null;
            await (outbound.streamSettings?.sockopt?.dialerProxy).Should().BeEqualTo(dialer);
        }
        await config.outbounds.Count(outbound => outbound.tag.Contains(tag, StringComparison.Ordinal)).Should().BeEqualTo(exitFirst.Count);
        await config.routing.rules.Any(rule => rule.domain?.Contains($"full:{RuleDomain}") == true && rule.outboundTag == tag).Should().BeTrue();
    }

    // ---- Xray

    [Test]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task ARuleToAProfileOfASubscriptionWithNeighboursRunsInsideTheirChain(bool withPrev, bool withNext)
    {
        var prev = XrayHop("prev", "198.51.100.1");
        var next = XrayHop("next", "198.51.100.3");
        var subId = await Subscription(withPrev ? prev.Remarks : null, withNext ? next.Remarks : null);
        var target = In(subId, XrayHop("target", "198.51.100.2"));
        await Store(prev, next, target);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var context = await Built(NewConfig(), main, target.Remarks);

        var hops = Hops(withPrev ? prev : null, target, withNext ? next : null);
        var chain = await AssertChain(context, target, hops);
        await AssertXrayChain(context, chain, hops);
        // The main profile, outside the subscription, stays alone.
        await context.Node.IndexId.Should().BeEqualTo(main.IndexId);
    }

    [Test]
    public async Task ARuleToAProfileOfASubscriptionWithoutNeighboursIsUnchanged()
    {
        var subId = await Subscription(null, null);
        var target = In(subId, XrayHop("target", "198.51.100.2"));
        await Store(target);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var context = await Built(NewConfig(), main, target.Remarks);

        await (RuleNode(context, target)?.IndexId).Should().BeEqualTo(target.IndexId);
        var generated = new CoreConfigV2rayService(context).GenerateClientConfigContent();
        await generated.Success.Should().BeTrue().Because(generated.Msg ?? string.Empty);
        var config = JsonUtils.Deserialize<V2rayConfig>(generated.Data!.ToString())!;
        var outbound = config.outbounds.Single(outbound => outbound.tag == RuleTag(target));
        await outbound.settings.address!.ToString().Should().BeEqualTo(target.Address);
        await (outbound.streamSettings?.sockopt?.dialerProxy).Should().BeNull();
    }

    [Test]
    public async Task ARulesSubscriptionNamingAProfileNoneHasWarnsAndLeavesItOutAsForTheMainProfile()
    {
        // The main profile's way (BuildSubscriptionChainNodeAsync): a warning for the name, and the chain without it.
        var missing = NewName("missing");
        var next = XrayHop("next", "198.51.100.3");
        var alone = In(await Subscription(missing, null), XrayHop("alone", "198.51.100.2"));
        var withNext = In(await Subscription(missing, next.Remarks), XrayHop("with-next", "198.51.100.4"));
        await Store(next, alone, withNext);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));
        var notFound = string.Format(ResUI.MsgSubscriptionPrevProfileNotFound, missing);

        var (aloneContext, aloneResult) = await BuildWithRuleTo(NewConfig(), main, alone.Remarks);
        await aloneResult.Success.Should().BeTrue();
        await aloneResult.Warnings.Should().Contain(string.Format(ResUI.MsgRoutingRuleOutboundNodeWarning, RuleName, alone.Remarks, notFound));
        await (RuleNode(aloneContext, alone)?.IndexId).Should().BeEqualTo(alone.IndexId);

        var (nextContext, nextResult) = await BuildWithRuleTo(NewConfig(), main, withNext.Remarks);
        await nextResult.Success.Should().BeTrue();
        await nextResult.Warnings.Should().Contain(string.Format(ResUI.MsgRoutingRuleOutboundNodeWarning, RuleName, withNext.Remarks, notFound));
        var chain = await AssertChain(nextContext, withNext, withNext, next);
        await AssertXrayChain(nextContext, chain, withNext, next);
    }

    // D1-R1: the traversal of the chain leaves out a hop that fails its checks, and without the profile the rule names the
    // rule would leave by its neighbours alone; it goes to the proxy, as when upstream resolves the profile alone.
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task ARuleToAProfileItsCoreCannotRunGoesToTheProxyAndNeverThroughItsNeighbours(bool withNext)
    {
        var prev = XrayHop("prev", "198.51.100.41");
        var next = XrayHop("next", "198.51.100.43");
        var target = In(await Subscription(prev.Remarks, withNext ? next.Remarks : null), TuicHop("tuic", "198.51.100.42"));
        await Store(prev, next, target);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var (context, result) = await BuildWithRuleTo(NewConfig(), main, target.Remarks);

        await result.Success.Should().BeTrue();
        await result.Warnings.Should().Contain(ChainLost(target, target));
        await RuleNode(context, target).Should().BeNull();
        await AssertNoneRegistered(context, prev, next, target);
        var g = await Succeeds(context);
        await g.Config.outbounds.Any(outbound => outbound.settings?.address?.ToString() is "198.51.100.41" or "198.51.100.43").Should().BeFalse();
        await g.Config.routing.rules.Any(rule => rule.domain?.Contains($"full:{RuleDomain}") == true && rule.outboundTag == Global.ProxyTag).Should().BeTrue();
    }

    // D1-R3: the routing services read the strategy of the rule's node, the chain; the group's own one counts.
    [Test]
    public async Task APolicyGroupARuleSendsToKeepsItsStrategyInsideItsSubscriptionsChain()
    {
        var prev = XrayHop("prev", "198.51.100.71");
        var first = XrayHop("first", "198.51.100.72");
        var second = XrayHop("second", "198.51.100.73");
        var group = CoreConfigTestFactory.CreatePolicyGroupNode(ECoreType.Xray, NewName("group"), NewName("group"), [first.IndexId, second.IndexId]);
        group.SetProtocolExtra(group.GetProtocolExtra() with { MultipleLoad = EMultipleLoad.Random });
        group = In(await Subscription(prev.Remarks, null), group);
        await Store(prev, first, second, group);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var context = await Built(NewConfig(), main, group.Remarks);

        var chain = await AssertChain(context, group, prev, group);
        var g = await Succeeds(context);
        var tag = RuleTag(chain);
        var balancer = g.Config.routing.balancers?.SingleOrDefault(balancer => balancer.tag == $"{tag}{Global.BalancerTagSuffix}");
        await (balancer?.strategy?.type).Should().BeEqualTo("random");
        // A random balancer measures nothing.
        await (g.Config.observatory?.subjectSelector?.Contains(tag) ?? false).Should().BeFalse();
        await (g.Config.burstObservatory?.subjectSelector?.Contains(tag) ?? false).Should().BeFalse();
        await g.Config.routing.rules.Any(rule => rule.domain?.Contains($"full:{RuleDomain}") == true && rule.balancerTag == balancer!.tag).Should().BeTrue();
    }

    // ---- sing-box in front of Xray (the legacy TUN)

    private static Config LegacyTunConfig()
    {
        return NewConfig(config =>
        {
            config.TunModeItem.EnableTun = true;
            config.TunModeItem.EnableLegacyProtect = true;
        });
    }

    // D1-R1, D1-R2: Xray, behind sing-box, routes the same rule with the whole chain, so sing-box sends the rule to it
    // rather than the way it can build without the profile itself or without a neighbour.
    [Test]
    public async Task InFrontOfXraySingBoxSendsARuleWhoseChainItCannotBuildWholeToXray()
    {
        var prev = XrayHop("prev", "198.51.100.61");
        var next = XrayHop("next", "198.51.100.63");
        var xhttpTarget = In(await Subscription(prev.Remarks, next.Remarks), XhttpHop("xhttp", "198.51.100.62"));
        var xhttpPrev = XhttpHop("xhttp-prev", "198.51.100.64");
        var rawTarget = In(await Subscription(xhttpPrev.Remarks, null), XrayHop("raw", "198.51.100.65"));
        await Store(prev, next, xhttpTarget, xhttpPrev, rawTarget);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        foreach (var (target, hops, lost) in new[]
                 {
                     (xhttpTarget, Hops(prev, xhttpTarget, next), xhttpTarget),
                     (rawTarget, Hops(xhttpPrev, rawTarget, null), xhttpPrev),
                 })
        {
            var built = await WithRuleTo(target.Remarks, () => CoreConfigContextBuilder.BuildAll(LegacyTunConfig(), main));

            await built.Success.Should().BeTrue();
            var front = built.PreSocksResult!;
            await front.ValidatorResult.Warnings.Should().Contain(ChainLost(target, lost));
            await RuleNode(front.Context, target).Should().BeNull();
            await AssertNoneRegistered(front.Context, hops);
            var behind = built.MainResult.Context;
            var chain = await AssertChain(behind, target, hops);
            await AssertXrayChain(behind, chain, hops);
        }
    }

    // Without a core behind it, a chain that lost a neighbour still carries the rule, as the main profile's does.
    [Test]
    public async Task WithoutACoreBehindARuleKeepsTheChainOfTheHopsItsCoreCanRun()
    {
        var tuicPrev = TuicHop("tuic-prev", "198.51.100.66");
        var target = In(await Subscription(tuicPrev.Remarks, null), XrayHop("raw", "198.51.100.67"));
        await Store(tuicPrev, target);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var context = await Built(NewConfig(), main, target.Remarks);

        var chain = RuleNode(context, target);
        await (chain?.ConfigType).Should().BeEqualTo(EConfigType.ProxyChain);
        await chain!.GetProtocolExtra().ChildItems.Should().BeEqualTo(target.IndexId);
    }

    // ---- sing-box

    [Test]
    [Arguments(true, false)]
    [Arguments(false, true)]
    [Arguments(true, true)]
    public async Task UnderSingBoxARuleToAProfileOfASubscriptionWithNeighboursRunsInsideTheirChain(bool withPrev, bool withNext)
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.sing_box);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var prev = SingboxHop("prev", "198.51.100.11");
        var next = SingboxHop("next", "198.51.100.13");
        var subId = await Subscription(withPrev ? prev.Remarks : null, withNext ? next.Remarks : null);
        var target = In(subId, SingboxHop("target", "198.51.100.12"));
        await Store(prev, next, target);
        var main = CoreConfigTestFactory.CreateSocksNode(ECoreType.sing_box, NewName("main"), NewName("main"));

        var context = await Built(config, main, target.Remarks);

        var hops = Hops(withPrev ? prev : null, target, withNext ? next : null);
        var chain = await AssertChain(context, target, hops);
        var generated = new CoreConfigSingboxService(context).GenerateClientConfigContent();
        await generated.Success.Should().BeTrue().Because(generated.Msg ?? string.Empty);
        var singbox = JsonUtils.Deserialize<SingboxConfig>(generated.Data!.ToString())!;
        var tag = RuleTag(chain);
        var exitFirst = hops.AsEnumerable().Reverse().ToList();
        for (var i = 0; i < exitFirst.Count; i++)
        {
            var outbound = singbox.outbounds.Single(outbound => outbound.tag == HopTag(tag, exitFirst, i));
            await outbound.server.Should().BeEqualTo(exitFirst[i].Address);
            await outbound.detour.Should().BeEqualTo(i + 1 < exitFirst.Count ? HopTag(tag, exitFirst, i + 1) : null);
        }
        await singbox.route.rules.Any(rule => rule.domain?.Contains(RuleDomain) == true && rule.outbound == tag).Should().BeTrue();
    }

    // D1-R1 under sing-box: a profile over xhttp, which sing-box cannot run.
    [Test]
    public async Task UnderSingBoxARuleToAProfileItCannotRunGoesToTheProxyAndNeverThroughItsNeighbours()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.sing_box);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var prev = SingboxHop("prev", "198.51.100.51");
        var next = SingboxHop("next", "198.51.100.53");
        var target = In(await Subscription(prev.Remarks, next.Remarks), XhttpHop("xhttp", "198.51.100.52"));
        await Store(prev, next, target);
        var main = CoreConfigTestFactory.CreateSocksNode(ECoreType.sing_box, NewName("main"), NewName("main"));

        var (context, result) = await BuildWithRuleTo(config, main, target.Remarks);

        await result.Success.Should().BeTrue();
        await result.Warnings.Should().Contain(ChainLost(target, target));
        await RuleNode(context, target).Should().BeNull();
        await AssertNoneRegistered(context, prev, next, target);
        var generated = new CoreConfigSingboxService(context).GenerateClientConfigContent();
        await generated.Success.Should().BeTrue().Because(generated.Msg ?? string.Empty);
        var singbox = JsonUtils.Deserialize<SingboxConfig>(generated.Data!.ToString())!;
        await singbox.outbounds.Any(outbound => outbound.server is "198.51.100.51" or "198.51.100.53").Should().BeFalse();
        await singbox.route.rules.Any(rule => rule.domain?.Contains(RuleDomain) == true && rule.outbound == Global.ProxyTag).Should().BeTrue();
    }

    // critique 4: sing-box runs no Aether profile, so the chain would run without WARP; the rule goes to the proxy, as
    // when sing-box is told to run the Aether profile alone, and never through the previous profile alone.
    [Test]
    public async Task UnderSingBoxARuleToAnAetherProfileOfAChainingSubscriptionGoesToTheProxy()
    {
        var config = CoreConfigTestFactory.CreateConfig(ECoreType.sing_box);
        CoreConfigTestFactory.BindAppManagerConfig(config);
        var prev = SingboxHop("prev", "198.51.100.11");
        var warp = In(await Subscription(prev.Remarks, null), Warp(NewName("warp"), NewName("WARP")));
        await Store(prev, warp);
        var main = CoreConfigTestFactory.CreateSocksNode(ECoreType.sing_box, NewName("main"), NewName("main"));

        var (context, result) = await BuildWithRuleTo(config, main, warp.Remarks);

        await result.Success.Should().BeTrue();
        var refusal = string.Format(ResUI.MsgAetherChainHopDropped, warp.Remarks, warp.Remarks);
        await result.Warnings.Should().Contain(string.Format(ResUI.MsgRoutingRuleOutboundNodeError, RuleName, warp.Remarks, refusal));
        await RuleNode(context, warp).Should().BeNull();
        var generated = new CoreConfigSingboxService(context).GenerateClientConfigContent();
        await generated.Success.Should().BeTrue().Because(generated.Msg ?? string.Empty);
        var singbox = JsonUtils.Deserialize<SingboxConfig>(generated.Data!.ToString())!;
        await singbox.outbounds.Any(outbound => outbound.server == prev.Address).Should().BeFalse();
        await singbox.route.rules.Any(rule => rule.domain?.Contains(RuleDomain) == true && rule.outbound == Global.ProxyTag).Should().BeTrue();
    }

    // ---- Aether

    [Test]
    public async Task ARuleToAnAetherProfileOfASubscriptionWithAPreviousProfileExitsThroughIt()
    {
        // Design 2.8, rows 5 and 6: the core dials out through the hop on the Aether hop's entry side, the exit-node.
        var prev = XrayHop("prev", "198.51.100.21");
        var warp = In(await Subscription(prev.Remarks, null), Warp(NewName("warp"), NewName("WARP")));
        await Store(prev, warp);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var context = await Built(NewConfig(), main, warp.Remarks);

        var chain = await AssertChain(context, warp, prev, warp);
        var g = await Succeeds(context);
        var ruleOutbound = g.Outbound(RuleTag(chain));
        await ruleOutbound.protocol.Should().BeEqualTo("socks");
        await ruleOutbound.settings.address!.ToString().Should().BeEqualTo(Global.Loopback);
        await ruleOutbound.settings.port.Should().BeEqualTo(AetherPorts.DefaultListenPort);
        await (ruleOutbound.streamSettings?.sockopt?.dialerProxy).Should().BeNull();
        var exitNode = g.Outbound(Global.AetherExitNodeTag);
        await exitNode.settings.address!.ToString().Should().BeEqualTo(prev.Address);
        await g.Core.Exit.Should().BeEqualTo(AetherExit.Through([prev]));
        await g.Outbound(Global.ProxyTag).protocol.Should().BeEqualTo("vmess");
    }

    [Test]
    public async Task ARuleToAProfileWhoseSubscriptionPutsAnAetherProfileInFrontRunsTheCore()
    {
        // Design 2.8, row 2: the Aether profile is the entry hop and dials out by its own exit-node; the rule's profile
        // carries the traffic. The configuration needs the core, as the WebAPI preflight reads it from the profiles the
        // context holds.
        var warp = Warp(NewName("warp"), NewName("WARP"));
        var target = In(await Subscription(warp.Remarks, null), XrayHop("target", "198.51.100.22"));
        await Store(warp, target);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var context = await Built(NewConfig(), main, target.Remarks);

        var chain = await AssertChain(context, target, warp, target);
        await context.AllProxiesMap.Values.Any(profile => profile.ConfigType == EConfigType.Aether).Should().BeTrue();
        var g = await Succeeds(context);
        var tag = RuleTag(chain);
        var ruleOutbound = g.Outbound(tag);
        await ruleOutbound.settings.address!.ToString().Should().BeEqualTo(target.Address);
        await (ruleOutbound.streamSettings?.sockopt?.dialerProxy).Should().BeEqualTo($"chain-{tag}-1-{warp.Remarks}");
        var hop = g.Outbound($"chain-{tag}-1-{warp.Remarks}");
        await hop.protocol.Should().BeEqualTo("socks");
        await hop.settings.port.Should().BeEqualTo(AetherPorts.DefaultListenPort);
        await g.Outbound(Global.AetherExitNodeTag).protocol.Should().BeEqualTo("freedom");
        await g.Core.Exit.Should().BeEqualTo(AetherExit.Plain);
    }

    [Test]
    public async Task ARuleToAnAetherProfileWhoseSubscriptionNamesAProfileNoneHasIsRefusedForTheRule()
    {
        // The main profile's chain is refused rather than shortened (AetherSubscriptionChainRefusal); a rule's goes to the
        // proxy with the refusal as a warning, as for any target that cannot be built.
        var missing = NewName("missing");
        var warp = In(await Subscription(missing, null), Warp(NewName("warp"), NewName("WARP")));
        await Store(warp);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        var (context, result) = await BuildWithRuleTo(NewConfig(), main, warp.Remarks);

        await result.Success.Should().BeTrue();
        var refusal = string.Format(ResUI.MsgAetherChainHopDropped, warp.Remarks, missing);
        await result.Warnings.Should().Contain(string.Format(ResUI.MsgRoutingRuleOutboundNodeError, RuleName, warp.Remarks, refusal));
        await RuleNode(context, warp).Should().BeNull();
        await context.AllProxiesMap.Should().NotContainKey(warp.IndexId);
        var g = await Succeeds(context);
        await g.Tags.Any(tag => tag.Contains(warp.Remarks, StringComparison.Ordinal)).Should().BeFalse();
        await g.Config.routing.rules.Any(rule => rule.domain?.Contains($"full:{RuleDomain}") == true && rule.outboundTag == Global.ProxyTag).Should().BeTrue();
        await g.Context.Aether.Core.Should().BeNull();

        // The main profile itself is refused for it.
        var (_, mainResult) = await BuildWithRuleTo(NewConfig(), warp, NewName("nobody"));
        await mainResult.Success.Should().BeFalse();
        await mainResult.Errors.Should().Contain(refusal);
    }

    // D1-R4: the WebAPI's preflight asks for the aether core when the context holds an Aether profile
    // (CoreLaunchPreflight.NeedsAether); a rule that goes to the proxy leaves none of the profiles it resolved behind.
    [Test]
    public async Task ARefusedRuleLeavesNoAetherProfileInTheContext()
    {
        var warp = Warp(NewName("warp"), NewName("WARP"));
        var behindWarp = In(await Subscription(warp.Remarks, null), TuicHop("tuic", "198.51.100.81"));
        var tuic = TuicHop("tuic", "198.51.100.82");
        var userChain = CoreConfigTestFactory.CreateProxyChainNode(ECoreType.Xray, NewName("chain"), NewName("chain"), [warp.IndexId, tuic.IndexId]);
        await Store(warp, behindWarp, tuic, userChain);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));

        // The subscription's chain, and a proxy chain the user made: each loses its TUIC hop, which Xray cannot run.
        foreach (var target in new[] { behindWarp, userChain })
        {
            var (context, result) = await BuildWithRuleTo(NewConfig(), main, target.Remarks);

            await result.Success.Should().BeTrue();
            await RuleNode(context, target).Should().BeNull();
            await context.AllProxiesMap.Values.Any(profile => profile.ConfigType == EConfigType.Aether).Should().BeFalse();
            await AssertNoneRegistered(context, warp, target);
            var g = await Succeeds(context);
            await g.Context.Aether.Core.Should().BeNull();
        }
    }

    [Test]
    public async Task ARulesChainIsHeldToTheOneCoreRule()
    {
        // One core cannot dial out two ways: the same tunnel as the main profile, alone, and behind the rule's chain.
        var prev = XrayHop("prev", "198.51.100.31");
        var warp = In(await Subscription(prev.Remarks, null), Warp(NewName("warp"), NewName("WARP")));
        await Store(prev, warp);
        var mainWarp = Warp(NewName("main-warp"), NewName("main WARP"));

        var twoExits = await Built(NewConfig(), mainWarp, warp.Remarks);
        await AssertChain(twoExits, warp, prev, warp);
        await Refused(twoExits, ResUI.MsgAetherConfigTwoExits);

        // A chain can have one Aether profile: the previous one of the subscription counts.
        var wg = Wg(NewName("wg"), NewName("WG"));
        var behindWg = In(await Subscription(wg.Remarks, null), Warp(NewName("warp"), NewName("WARP")));
        await Store(wg, behindWg);
        var main = CoreConfigTestFactory.CreateVmessNode(ECoreType.Xray, NewName("main"), NewName("main"));
        var twoTunnels = await Built(NewConfig(), main, behindWg.Remarks);
        await AssertChain(twoTunnels, behindWg, wg, behindWg);
        await Refused(twoTunnels, ResUI.MsgAetherChainOneProfile);
    }
}
