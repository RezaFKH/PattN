namespace ServiceLib.Handler.Builder;

/// <summary>
/// PattN: the profile a routing rule sends to, which runs inside its subscription's previous/next chain as the main
/// profile does (D1; PattNG CoreConfigContextBuilder.kt resolveOutbound). A chain that lost a hop it needs cannot carry
/// the rule, which then goes to the proxy as for any target that cannot be built; what resolving the target added to the
/// context is taken back then, so that nothing outside the configuration reads a profile it never runs.
/// </summary>
public partial class CoreConfigContextBuilder
{
    /// <summary>
    /// Why the chain <paramref name="resolved" /> that the subscription of <paramref name="target" /> put around it cannot
    /// carry a routing rule, as a result with that error and the warnings of <paramref name="resolution" />; null when it
    /// can, or when <paramref name="resolved" /> is the target itself. The traversal of a chain leaves out a hop that fails
    /// its checks with a warning, which would send the rule a shorter way than its subscription names:
    /// <list type="bullet">
    /// <item>without the target itself, the rule would leave by its neighbours alone and never reach the profile it names;</item>
    /// <item>
    /// with <paramref name="carriedBehind" />, the context is the one of the core in front of another (sing-box in front of
    /// Xray under the legacy TUN) whose routing has the same rule and builds the same chain with its own checks: the rule
    /// goes to that core, the proxy here, rather than the way this core can build without a neighbour.
    /// </item>
    /// </list>
    /// </summary>
    private static async Task<NodeValidatorResult?> RuleChainShortfallAsync(
        ProfileItem target,
        ProfileItem resolved,
        NodeValidatorResult resolution,
        bool carriedBehind)
    {
        if (resolved.IndexId == target.IndexId || resolved.ConfigType != EConfigType.ProxyChain)
        {
            return null;
        }
        // The traversal leaves the hops it built in the chain's ChildItems.
        var built = (Utils.String2List(resolved.GetProtocolExtra().ChildItems) ?? []).ToHashSet();
        string? lost = null;
        if (!built.Contains(target.IndexId))
        {
            lost = target.Remarks;
        }
        else if (carriedBehind)
        {
            // The hops the subscription names, as BuildSubscriptionChainNodeAsync found them for the chain.
            var (named, _) = await BuildSubscriptionChainNodeAsync(target);
            if ((Utils.String2List(named?.GetProtocolExtra().ChildItems) ?? []).FirstOrDefault(id => !built.Contains(id)) is { } lostId)
            {
                lost = (await AppManager.Instance.GetProfileItem(lostId))?.Remarks ?? lostId;
            }
        }
        if (lost == null)
        {
            return null;
        }
        Logging.SaveLog($"Routing rule target '{target.Remarks}': the chain of its subscription lost '{lost}'; the rule goes to the proxy");
        return new NodeValidatorResult([string.Format(ResUI.MsgRoutingRuleChainHopNotBuilt, lost)], resolution.Warnings);
    }

    /// <summary>
    /// A policy group a rule sends to keeps its own strategy inside the chain of its subscription: the routing services
    /// read the strategy of the rule's node, the chain, which would otherwise have none and balance by the lowest ping.
    /// </summary>
    private static void KeepRuleGroupStrategy(ProfileItem target, ProfileItem resolved)
    {
        if (target.ConfigType != EConfigType.PolicyGroup || resolved.IndexId == target.IndexId)
        {
            return;
        }
        resolved.SetProtocolExtra(resolved.GetProtocolExtra() with { MultipleLoad = target.GetProtocolExtra().MultipleLoad });
    }

    /// <summary>
    /// What registering profiles adds to a context: the proxies, the protected names, the custom outbounds read and the
    /// exit-nodes looked up; taken before the profile of a routing rule is resolved and given back when the rule cannot
    /// use it. The WebAPI's preflight reads the proxies to tell whether the configuration needs the Aether core.
    /// </summary>
    private sealed class RuleTargetState
    {
        private readonly Dictionary<string, ProfileItem> _proxies;
        private readonly HashSet<string> _protectDomains;
        private readonly Dictionary<string, string> _customOutbounds;
        private readonly Dictionary<string, ExitNodeLookup> _exitNodes;

        private RuleTargetState(CoreConfigContext context)
        {
            _proxies = new Dictionary<string, ProfileItem>(context.AllProxiesMap);
            _protectDomains = [.. context.ProtectDomainList];
            _customOutbounds = new Dictionary<string, string>(context.CustomOutboundContent);
            _exitNodes = new Dictionary<string, ExitNodeLookup>(context.Aether.ExitNodes);
        }

        public static RuleTargetState Of(CoreConfigContext context)
        {
            return new RuleTargetState(context);
        }

        public void Restore(CoreConfigContext context)
        {
            Refill(context.AllProxiesMap, _proxies);
            context.ProtectDomainList.Clear();
            context.ProtectDomainList.UnionWith(_protectDomains);
            Refill(context.CustomOutboundContent, _customOutbounds);
            Refill(context.Aether.ExitNodes, _exitNodes);
        }

        private static void Refill<TValue>(Dictionary<string, TValue> target, Dictionary<string, TValue> saved)
        {
            target.Clear();
            foreach (var (key, value) in saved)
            {
                target[key] = value;
            }
        }
    }
}
