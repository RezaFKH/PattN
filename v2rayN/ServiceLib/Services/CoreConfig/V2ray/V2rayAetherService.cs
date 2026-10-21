namespace ServiceLib.Services.CoreConfig;

/// <summary>
/// PattN: how Xray reaches an Aether core, and how what the core sends out leaves through Xray (design 2.7, 2.8;
/// PattNG core/CoreConfigManager.kt and core/CoreOutboundBuilder.kt). An Aether profile's outbound is a SOCKS one to
/// its core on the loopback address. The core dials out through Xray's secondary-socks inbound, three ports above the
/// Aether listen port, which a rule ahead of every other sends out by the outbound tagged exit-node: a freedom one with
/// the profile's finalMask and dialMode, the outbound of the profile it names as its exit-node, or the hop on the entry
/// side of its hop in a proxy chain. One core runs per configuration, so every Aether outbound has to need the same one.
/// </summary>
public partial class CoreConfigV2rayService
{
    /// <summary>The Aether listen port of the settings this configuration is built with.</summary>
    private int AetherListenPort => AetherPorts.ListenPortOf(_config.CoreBasicItem.AetherListenPort);

    #region public gen function

    /// <summary>
    /// The configuration of a short-lived Xray that a core of its own (a scan, a key run) dials out through (design
    /// 2.6.5, PattNG AetherCoreManager.exitConfiguration): the secondary-socks inbound on <paramref name="port" />, the
    /// exit-node of <paramref name="exit" /> (see <see cref="BuildAetherExitOutbound" />) with the ECH outbound of a
    /// node linked as in a session, and the rule between them. The node is looked up in the context's
    /// <see cref="AetherBuild.ExitNodes" />, which the caller fills (CoreConfigContextBuilder.LookUpAetherExitNodeAsync).
    /// A node that gives no outbound opens no exit: the core would reach the internet without it.
    /// </summary>
    public RetResult GenerateAetherExitConfig(AetherExit exit, int port)
    {
        var ret = new RetResult();
        try
        {
            var result = EmbedUtils.GetEmbedText(Global.V2raySampleClient);
            if (result.IsNullOrEmpty())
            {
                ret.Msg = ResUI.FailedGetDefaultConfiguration;
                return ret;
            }
            _coreConfig = JsonUtils.Deserialize<V2rayConfig>(result);
            if (_coreConfig == null)
            {
                ret.Msg = ResUI.FailedGenDefaultConfiguration;
                return ret;
            }

            context.EchOutbounds.Clear();
            context.Aether.Reset();
            GenLog();
            var exitNode = BuildAetherExitOutbound(exit, out var failure);
            if (exitNode == null)
            {
                ret.Msg = failure;
                return ret;
            }
            _coreConfig.inbounds = [BuildAetherSecondaryInbound(port)];
            _coreConfig.outbounds = [exitNode];
            _coreConfig.routing = new Routing4Ray { domainStrategy = Global.AsIs, rules = [BuildAetherExitRule()] };
            if (context.IsTunEnabled)
            {
                // The freedom exit-node resolves with Xray's DNS under the TUN (ForceIP): with the direct DNS servers, as
                // the session's protected names are, rather than the system resolver, whose queries enter the TUN and may
                // reach a remote DNS through the very core that is starting (critique 19).
                _coreConfig.dns = BuildAetherExitDns();
            }

            ApplyOutboundBindInterface();
            ApplyOutboundSendThrough();
            var coreConfigContent = ApplyCustomOutboundReplace();
            var echOutboundError = AppendEchOutbounds(ref coreConfigContent);
            if (echOutboundError != null)
            {
                ret.Msg = echOutboundError;
                return ret;
            }

            ret.Msg = string.Format(ResUI.SuccessfulConfiguration, "");
            ret.Success = true;
            ret.Data = coreConfigContent;
            return ret;
        }
        catch (Exception ex)
        {
            Logging.SaveLog(_tag, ex);
            ret.Msg = ResUI.FailedGenDefaultConfiguration;
            return ret;
        }
    }

    #endregion public gen function

    #region outbounds

    /// <summary>
    /// The outbound of the Aether profile being built (PattNG toOutboundAether): a SOCKS one to the core on the loopback
    /// address, on the port it listens on, without mux, and without stream settings: no TLS, finalMask or dialMode,
    /// which belong to the exit-node the core's own traffic leaves by.
    /// </summary>
    private void FillAetherOutbound(Outbounds4Ray outbound)
    {
        outbound.protocol = Global.ProtocolTypes[EConfigType.Aether];
        outbound.settings.address = Global.Loopback;
        outbound.settings.port = AetherCore.Of(_node, AetherListenPort).Port;
        FillOutboundMux(outbound);
        outbound.streamSettings = null;
    }

    /// <summary>
    /// Records the outbound of the Aether profile being built, for GenAether, and gives it its targetStrategy: the one
    /// its profile stores, or the default of where its traffic leaves (<see cref="AetherOutbound.TargetStrategyOf" />).
    /// Its tag is set by its caller; a chain hop's exit is set by the chain (<see cref="AetherChainLayout" />).
    /// </summary>
    private void RecordAetherOutbound(Outbounds4Ray outbound)
    {
        outbound.targetStrategy = AetherOutbound.TargetStrategyOf(_node);
        context.Aether.Add(outbound, new AetherUse(_node, AetherCore.Of(_node, AetherListenPort)));
    }

    /// <summary>
    /// Refuses the configuration when <paramref name="childOutbounds" />, the outbounds of the group or the chain
    /// <paramref name="hop" /> that is a hop of a proxy chain, hold an Aether outbound (critique 3): the chain gives its
    /// members a dialer, so Xray would dial the core's loopback address through a remote hop, and the core's own way out
    /// would be the group's, which is no single hop.
    /// </summary>
    private void RefuseAetherInGroupHop(ProfileItem hop, IEnumerable<Outbounds4Ray> childOutbounds)
    {
        var use = childOutbounds.Select(context.Aether.UseOf).FirstOrDefault(found => found != null);
        if (use != null)
        {
            context.Aether.Refuse(string.Format(ResUI.MsgAetherInGroupHop, hop.Remarks, use.Profile.Remarks));
        }
    }

    /// <summary>
    /// The exit-node of a core that dials out through <paramref name="exit" /> (PattNG toOutboundAetherExit), tagged
    /// exit-node: the outbound of the profile its node names, built as a proxy chain builds a hop and passing every name
    /// on as it is, whatever its profile sets, since a name Xray looked up for it would be asked of the DNS that reaches
    /// out through the core itself, which is not up yet when it needs the name; or else a freedom one with the finalMask
    /// and the dialMode of <paramref name="exit" />, set as an ordinary profile sets them on its own outbound, and, under
    /// the TUN, resolving names with Xray's DNS, as the direct outbound does. Null, with the localized
    /// <paramref name="failure" />, when the node gives none: no profile has the name any more, several have it, or the
    /// one that has it gives no outbound or an unusable ECH outbound; the core would reach the internet without it.
    /// </summary>
    private Outbounds4Ray? BuildAetherExitOutbound(AetherExit exit, out string? failure)
    {
        failure = null;
        if (exit.Node != null)
        {
            var lookup = context.Aether.ExitNodes.GetValueOrDefault(exit.Node) ?? ExitNodeLookup.NotFound.Instance;
            if (lookup is not ExitNodeLookup.One one)
            {
                var problem = (ExitNodeLookup.Problem)lookup;
                Logging.SaveLog($"{_tag}: the exit-node profile the Aether core dials out through gives no exit-node ({problem.GetType().Name})");
                failure = string.Format(ResUI.ResourceManager.GetString(problem.MessageKey, ResUI.Culture) ?? problem.MessageKey, exit.Node);
                return null;
            }
            var node = new CoreConfigV2rayService(context with { Node = one.Profile }).BuildProxyOutbound(Global.AetherExitNodeTag);
            node.tag = Global.AetherExitNodeTag;
            node.targetStrategy = null;
            return node;
        }

        var freedom = new Outbounds4Ray { tag = Global.AetherExitNodeTag, protocol = "freedom" };
        if (!KotlinText.IsBlank(exit.FinalMask) && JsonUtils.ParseJson(exit.FinalMask) is JsonObject finalMask)
        {
            // A freedom outbound has no transport; the stream settings carry the mask alone.
            freedom.streamSettings = new StreamSettings4Ray { finalmask = finalMask };
        }
        if (!KotlinText.IsBlank(exit.DialMode))
        {
            freedom.streamSettings ??= new();
            freedom.streamSettings.sockopt ??= new();
            freedom.streamSettings.sockopt.dialMode = exit.DialMode;
        }
        if (context.IsTunEnabled)
        {
            // The names the core hands over would otherwise be looked up by the OS resolver, whose queries enter the TUN.
            FillAetherExitResolution(freedom);
        }
        return freedom;
    }

    /// <summary>
    /// How the freedom exit-node resolves the names the core hands over under the TUN (design 2.7.6 point 2): with Xray's
    /// DNS, as the direct outbound does, by the family the direct outbound's strategy asks for, and racing the addresses
    /// it finds with the happyEyeballs the direct outbound has (Xray dials one address at random without it). The
    /// strategy is always a Force one: a Use one falls back to the OS resolver when Xray's DNS finds nothing, and that
    /// query enters the TUN, where it would reach the remote DNS through the core that is starting.
    /// </summary>
    private void FillAetherExitResolution(Outbounds4Ray freedom)
    {
        var rawDns = context.RawDnsItem is { Enabled: true };
        var freedomStrategy = rawDns ? context.RawDnsItem!.DomainStrategy4Freedom : context.SimpleDnsItem?.Strategy4Freedom;
        // GenDns gives the direct outbound the happyEyeballs of the settings along with a strategy of the simple DNS
        // settings other than AsIs; it keeps the sample's otherwise.
        var directStrategySet = !rawDns && !freedomStrategy.IsNullOrEmpty() && freedomStrategy != Global.AsIs;
        FillSockoptDomainStrategy(freedom, AetherOutbound.ForcedStrategyOf(freedomStrategy), skipHappyEyeballs: !directStrategySet);
        var direct = _coreConfig.outbounds?.FirstOrDefault(outbound => outbound is { protocol: "freedom", tag: Global.DirectTag });
        if (direct?.streamSettings?.sockopt?.happyEyeballs is { } happyEyeballs)
        {
            freedom.streamSettings!.sockopt!.happyEyeballs ??= JsonUtils.DeepCopy(happyEyeballs);
        }
    }

    /// <summary>
    /// Whether the global "Proxy Target Resolution Strategy" passes <paramref name="outbound" /> by (critique 6): an
    /// Aether outbound keeps the default of where its traffic leaves (a core that leaves through Tor or Psiphon looks
    /// names up at their exit), and the exit-node passes every name the core sends on as it is.
    /// </summary>
    private bool KeepsAetherTargetStrategy(Outbounds4Ray outbound)
    {
        return context.Aether.IsAetherOutbound(outbound) || outbound.tag == Global.AetherExitNodeTag;
    }

    /// <summary>
    /// A latency test has no DNS: a name an outbound had Xray look up would be asked of the system's own resolver,
    /// outside the tunnel the test measures (critique 7, PattNG trimOutboundsForSpeedtest). The Aether outbounds and the
    /// exit-node pass every name on as it is.
    /// </summary>
    private void TrimAetherOutboundsForTest()
    {
        foreach (var outbound in _coreConfig.outbounds.Where(KeepsAetherTargetStrategy))
        {
            outbound.targetStrategy = null;
        }
    }

    #endregion outbounds

    #region GenAether

    /// <summary>
    /// Settles on the one Aether core the outbounds of this configuration need, and has what it sends out leave through
    /// Xray (design 2.7.3): the secondary-socks inbound on <paramref name="secondaryPort" />, with no sniffing, so that
    /// the destination the core gives is used as is; the exit-node, after every other outbound, unless a hop of a chain
    /// the core dials out through is the exit-node already; and a rule ahead of every other, which no user rule, DNS rule
    /// or balancer meets, so that nothing the core sends loops back into an Aether outbound. A core whose command names
    /// an upstream of its own is left as it is. The core is left in <see cref="AetherBuild.Core" />, its command in the
    /// configuration's aetherCommand. Returns the localized reason the configuration cannot run, or null.
    /// <paramref name="forTest" /> leaves the named exit-node without the global dial strategy of a session, which a
    /// test configuration has no DNS for.
    /// </summary>
    private string? GenAether(int secondaryPort, bool forTest)
    {
        var core = SettleAetherCore(out var failure);
        if (core == null)
        {
            return failure;
        }
        // Ports the app holds besides its inbounds: Xray's metrics listener and the API of sing-box or mihomo, which an
        // inbound check cannot see (critique 10).
        var routed = !core.HasUpstream;
        var statePort = AppStatePorts().FirstOrDefault(port => core.Ports.Contains(port) || (routed && port == secondaryPort));
        if (statePort != 0)
        {
            Logging.SaveLog($"{_tag}: the Aether core would listen on {statePort}, a port the app holds");
            return ResUI.MsgAetherListenPortTaken;
        }
        if (!routed)
        {
            context.Aether.Core = core;
            _coreConfig.aetherCommand = core.Command;
            return null;
        }
        if (_coreConfig.inbounds.Any(inbound => inbound.port == secondaryPort))
        {
            Logging.SaveLog($"{_tag}: an inbound of the configuration listens on the Aether secondary SOCKS port {secondaryPort}");
            return string.Format(ResUI.MsgAetherSecondaryPortTaken, secondaryPort);
        }

        Outbounds4Ray? exitNode = null;
        if (!HasAetherExitNode())
        {
            exitNode = BuildAetherExitOutbound(core.Exit, out failure);
            if (exitNode == null)
            {
                return failure;
            }
            if (!forTest && core.Exit.Node != null)
            {
                // The exit-node joins after GenDns: the domains it dials are resolved as those of the other proxies are
                // (critique 18). A freedom one keeps its own.
                ApplyProxyDialStrategy(exitNode);
            }
        }

        _coreConfig.inbounds.Add(BuildAetherSecondaryInbound(secondaryPort));
        if (exitNode != null)
        {
            _coreConfig.outbounds.Add(exitNode);
        }
        _coreConfig.routing.rules.Insert(0, BuildAetherExitRule());

        core = core.Through(secondaryPort);
        if (exitNode != null && core.Exit.Node != null
            && context.Aether.ExitNodes.GetValueOrDefault(core.Exit.Node) is ExitNodeLookup.One one)
        {
            // The key of the exit-node carries the content of that profile, so that a test tells it from a changed one.
            core = core with { Exit = core.Exit with { NodeContent = one.Content } };
        }
        context.Aether.Core = core;
        _coreConfig.aetherCommand = core.Command;
        return null;
    }

    /// <summary>
    /// The one core the Aether outbounds of this configuration need (PattNG AetherDependency.of with aetherFailure and
    /// lacksChainHop): null with no Aether outbound at all, or with the localized <paramref name="failure" /> when one core
    /// cannot serve them: a refusal the builders recorded, a chain with two Aether hops, two Aether profiles with other
    /// settings, one tunnel that would dial out two ways, or a chain hop the core dials out through that was not built.
    /// </summary>
    private AetherCore? SettleAetherCore(out string? failure)
    {
        var aether = context.Aether;
        foreach (var outbound in aether.Outbounds)
        {
            aether.UseOf(outbound)!.Tag ??= outbound.tag;
        }
        failure = aether.Failure;
        if (failure != null)
        {
            Logging.SaveLog($"{_tag}: Aether cannot serve this configuration: {failure}");
            return null;
        }
        var dependency = AetherDependency.Of(aether.Uses);
        failure = dependency switch
        {
            AetherDependency.TwoAetherHops => ResUI.MsgAetherChainOneProfile,
            AetherDependency.Conflicting => ResUI.MsgAetherConfigSingleProfile,
            AetherDependency.TwoExits => ResUI.MsgAetherConfigTwoExits,
            _ => null,
        };
        if (failure != null)
        {
            Logging.SaveLog($"{_tag}: Aether cannot serve this configuration: {dependency.GetType().Name}");
            return null;
        }
        if (dependency is not AetherDependency.Single single)
        {
            return null;
        }
        if (single.Core.Exit.Hops != null && !HasAetherExitNode())
        {
            Logging.SaveLog($"{_tag}: the chain hop the Aether core dials out through could not be built");
            failure = ResUI.MsgAetherChainHopMissing;
            return null;
        }
        return single.Core;
    }

    /// <summary>
    /// The reason the configuration cannot run that the Aether outbounds give, without routing their core through Xray:
    /// for a latency test whose core is the live session's, which dials out through the session's own Xray.
    /// </summary>
    private string? CheckAether()
    {
        SettleAetherCore(out var failure);
        return failure;
    }

    /// <summary>
    /// Why the configuration <paramref name="content" />, as it is handed to Xray, cannot run beside its Aether core:
    /// the full-configuration template refused it (<see cref="ApplyAetherToTemplate" />), or an inbound of its own, a
    /// template's among them, listens on a port the core listens on (PattNG CoreServiceManager): Xray would take the port
    /// first, and the Aether outbound would dial the configuration's own inbound. The core is none then. Null when it can,
    /// or when no core runs.
    /// </summary>
    private string? CheckAetherConfig(string content)
    {
        var failure = context.Aether.Failure;
        if (failure == null && context.Aether.Core is { } core
            && core.Ports.FirstOrDefault(listened => AetherDependency.InboundListensOn(content, listened)) is var port and not 0)
        {
            Logging.SaveLog($"{_tag}: an inbound of the configuration listens on the Aether port {port}");
            failure = ResUI.MsgAetherListenPortTaken;
        }
        if (failure != null)
        {
            context.Aether.Core = null;
        }
        return failure;
    }

    /// <summary>
    /// The full-configuration template takes the place of the generated inbounds and routing (design 2.7.7): the
    /// secondary-socks inbound and its rule go into the template's, unless an inbound of the template listens on that
    /// port already, or a balancer or an observatory of the template picks the exit-node by its selector (PattNG
    /// AetherDependency.routeThroughXray), either of which refuses the configuration (<see cref="AetherBuild.Refuse" />):
    /// what such a balancer sends could leave by the exit-node, directly where it is a freedom one.
    /// </summary>
    private void ApplyAetherToTemplate(JsonNode templateNode)
    {
        var secondary = _coreConfig.inbounds?.FirstOrDefault(inbound => inbound.tag == Global.AetherSecondarySocksTag);
        if (context.Aether.Core == null || secondary?.port is not { } port || templateNode is not JsonObject template)
        {
            return;
        }
        if (AetherDependency.InboundListensOn(template.ToJsonString(), port))
        {
            Logging.SaveLog($"{_tag}: an inbound of the full configuration template listens on the Aether secondary SOCKS port {port}");
            context.Aether.Refuse(string.Format(ResUI.MsgAetherSecondaryPortTaken, port));
            return;
        }
        if (ExitNodeSelector(template) is { } selector)
        {
            Logging.SaveLog($"{_tag}: a balancer or an observatory of the full configuration template picks the outbounds whose tags start with \"{selector}\", the exit-node among them");
            context.Aether.Refuse(string.Format(ResUI.MsgAetherTemplateExitNodeSelected, selector));
            return;
        }
        if (template["inbounds"] is not JsonArray inbounds)
        {
            inbounds = [];
            template["inbounds"] = inbounds;
        }
        inbounds.Add(JsonNode.Parse(JsonUtils.Serialize(secondary, false)));
        if (template["routing"] is not JsonObject routing)
        {
            routing = [];
            template["routing"] = routing;
        }
        if (routing["rules"] is not JsonArray rules)
        {
            rules = [];
            routing["rules"] = rules;
        }
        rules.Insert(0, JsonNode.Parse(JsonUtils.Serialize(BuildAetherExitRule(), false)));
    }

    /// <summary>
    /// The first selector of the balancers of <paramref name="template" />, or of its observatories, that the tag of the
    /// exit-node starts with (PattNG AetherDependency.exitNodeSelector): those pick the outbounds whose tags start with a
    /// selector. Null when there is none.
    /// </summary>
    private static string? ExitNodeSelector(JsonObject template)
    {
        var balancers = (template["routing"] as JsonObject)?["balancers"] as JsonArray ?? [];
        var selectors = balancers.SelectMany(balancer => TextsAt(balancer, "selector"))
            .Concat(new[] { "observatory", "burstObservatory" }.SelectMany(key => TextsAt(template[key], "subjectSelector")));
        return selectors.FirstOrDefault(selector => Global.AetherExitNodeTag.StartsWith(selector, StringComparison.Ordinal));

        static IEnumerable<string> TextsAt(JsonNode? node, string key)
        {
            return ((node as JsonObject)?[key] as JsonArray ?? [])
                .OfType<JsonValue>()
                .Select(value => value.TryGetValue<string>(out var text) ? text : null)
                .OfType<string>();
        }
    }

    /// <summary>
    /// <paramref name="configNode" /> with the command line of the Aether core first, as aetherCommand, the way the
    /// generated configuration has it, so that an exported configuration names its core (critique 14).
    /// </summary>
    private JsonNode WithAetherCommandFirst(JsonNode configNode)
    {
        if (context.Aether.Core is not { } core || configNode is not JsonObject config)
        {
            return configNode;
        }
        var ordered = new JsonObject { ["aetherCommand"] = core.Command };
        foreach (var (key, value) in config.ToList())
        {
            config.Remove(key);
            if (key != "aetherCommand")
            {
                ordered[key] = value;
            }
        }
        return ordered;
    }

    /// <summary>The names of the Aether outbounds, for the template, which works on the serialized configuration.</summary>
    private HashSet<string> AetherOutboundTags()
    {
        return context.Aether.Outbounds.Select(outbound => outbound.tag).ToHashSet();
    }

    /// <summary>The dial strategy of the DNS settings for the proxies, as GenDns gives it to theirs.</summary>
    private void ApplyProxyDialStrategy(Outbounds4Ray outbound)
    {
        if (context.RawDnsItem is { Enabled: true })
        {
            return;
        }
        var strategy4DialProxy = context.SimpleDnsItem?.Strategy4ProxyDial ?? Global.AsIs;
        if (strategy4DialProxy.IsNullOrEmpty() || strategy4DialProxy == Global.AsIs)
        {
            return;
        }
        var xraySupportConfigTypeNames = Global.XraySupportConfigType
            .Select(x => x == EConfigType.Hysteria2 ? "hysteria" : Global.ProtocolTypes[x])
            .ToHashSet();
        if (xraySupportConfigTypeNames.Contains(outbound.protocol))
        {
            FillSockoptDomainStrategy(outbound, strategy4DialProxy);
        }
    }

    private bool HasAetherExitNode()
    {
        return _coreConfig.outbounds.Any(outbound => outbound.tag == Global.AetherExitNodeTag);
    }

    /// <summary>
    /// The ports the app holds that are no inbound of an Xray configuration: StatePort, Xray's metrics listener, and
    /// StatePort2, the API of sing-box or mihomo (one higher under the TUN), either of which can be a port the system gave
    /// in place of a busy one; and the port of the PAC server, three above the local proxy port of the configuration
    /// (AppManager.GetLocalPort), which the system proxy's PAC mode on Windows listens on. The PAC port counts whatever
    /// mode is on, as every port of the app from the local proxy port on does for the Aether listen port (design 2.5.1).
    /// </summary>
    private List<int> AppStatePorts()
    {
        var localPort = _config.Inbound?.FirstOrDefault(inbound => inbound.Protocol == nameof(EInboundProtocol.socks))?.LocalPort ?? 10808;
        var pacPort = localPort + (int)EInboundProtocol.pac;
        var app = AppManager.Instance;
        return app.Config == null ? [pacPort] : [app.StatePort, app.StatePort2, pacPort];
    }

    /// <summary>
    /// The DNS of the exit Xray under the TUN: the direct DNS servers of the settings, a server named by its domain looked
    /// up with the bootstrap DNS first, as the session's DNS does it.
    /// </summary>
    private Dns4Ray BuildAetherExitDns()
    {
        var direct = DnsAddresses(context.SimpleDnsItem?.DirectDNS, Global.DomainDirectDNSAddress.First());
        var bootstrap = DnsAddresses(context.SimpleDnsItem?.BootstrapDNS, Global.DomainPureIPDNSAddress.First());
        var serverDomains = direct
            .Select(address => Utils.ParseUrl(address).Item1)
            .Where(host => host != "localhost" && Utils.IsDomain(host))
            .Select(host => $"full:{host}")
            .ToList();
        var options = new JsonSerializerOptions { DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
        var servers = new List<object>();
        if (serverDomains.Count > 0)
        {
            foreach (var address in bootstrap)
            {
                var server = DnsServer(address);
                server.domains = serverDomains;
                server.finalQuery = true;
                servers.Add(JsonUtils.SerializeToNode(server, options)!);
            }
        }
        servers.AddRange(direct.Select(address => (object)JsonUtils.SerializeToNode(DnsServer(address), options)!));
        return new Dns4Ray { servers = servers };

        static List<string> DnsAddresses(string? text, string fallback)
        {
            var addresses = (Utils.String2List(text) ?? [])
                .Select(address => address.Trim())
                .Where(address => address.Length > 0)
                .Select(address => address.StartsWith("dhcp", StringComparison.OrdinalIgnoreCase) ? "localhost" : address)
                .Distinct()
                .ToList();
            return addresses.Count > 0 ? addresses : [fallback];
        }

        static DnsServer4Ray DnsServer(string address)
        {
            var (host, scheme, port, _) = Utils.ParseUrl(address);
            if (scheme.IsNullOrEmpty() || scheme.StartsWith("udp", StringComparison.OrdinalIgnoreCase))
            {
                return new DnsServer4Ray { address = host, port = port > 0 ? port : null };
            }
            if (scheme.StartsWith("tcp", StringComparison.OrdinalIgnoreCase))
            {
                return new DnsServer4Ray { address = $"{scheme}://{host}", port = port > 0 ? port : null };
            }
            return new DnsServer4Ray { address = address };
        }
    }

    private static Inbounds4Ray BuildAetherSecondaryInbound(int port)
    {
        return new Inbounds4Ray
        {
            tag = Global.AetherSecondarySocksTag,
            listen = Global.Loopback,
            port = port,
            protocol = nameof(EInboundProtocol.mixed),
            settings = new Inboundsettings4Ray { auth = "noauth", udp = true },
        };
    }

    private static RulesItem4Ray BuildAetherExitRule()
    {
        return new RulesItem4Ray
        {
            type = "field",
            inboundTag = [Global.AetherSecondarySocksTag],
            outboundTag = Global.AetherExitNodeTag,
        };
    }

    #endregion GenAether

    /// <summary>
    /// PattN: where the Aether hop of a proxy chain stands, and what that changes in the chain (design 2.8, PattNG
    /// handleProxyChainResolvedOutbound). The hops are those of the chain from the exit hop to the entry hop, as Xray
    /// dials them. The Aether hop dials through no hop by its outbound, which only reaches the core on the loopback
    /// address; the hop on its entry side carries the core's own traffic instead, as the outbound tagged exit-node, and
    /// the hops further on its entry side dial on as before. A second chain whose Aether hop dials out through the same
    /// hops keeps its own copy of that hop under its own tag; the core is one, as both exits are the same digest.
    /// </summary>
    private sealed class AetherChainLayout
    {
        private readonly CoreConfigContext _context;
        private readonly List<ProfileItem> _hops;
        private readonly int _aetherHop = -1;
        private readonly int _exitHop = -1;
        private readonly bool _takesExitTag;
        private readonly string _chainTag;

        public AetherChainLayout(CoreConfigContext context, ProfileItem chain, List<ProfileItem> hops, string baseTagName)
        {
            _context = context;
            _hops = hops;
            _chainTag = context.Aether.NewChainTag(baseTagName);
            var aetherHops = hops.Select((hop, index) => hop.ConfigType == EConfigType.Aether ? index : -1).Where(index => index >= 0).ToList();
            if (aetherHops.Count > 1)
            {
                context.Aether.Refuse(ResUI.MsgAetherChainOneProfile);
                return;
            }
            if (aetherHops.Count == 0)
            {
                return;
            }
            _aetherHop = aetherHops[0];
            // One outbound has to be the exit-node: a policy group or a chain on the entry side would give several.
            if (hops.Skip(_aetherHop + 1).Any(hop => hop.ConfigType.IsGroupType()))
            {
                context.Aether.Refuse(string.Format(ResUI.MsgAetherChainHopGroup, chain.Remarks));
                return;
            }
            if (_aetherHop + 1 < hops.Count)
            {
                _exitHop = _aetherHop + 1;
                _takesExitTag = !context.Aether.ExitNodeTagTaken;
                context.Aether.ExitNodeTagTaken = true;
            }
        }

        /// <summary>
        /// The tag of hop <paramref name="index" /> and the tag of the hop it dials through, given the ones the chain
        /// gives them otherwise: the hop the Aether hop dials out through is the exit-node, and the Aether hop dials
        /// through nothing.
        /// </summary>
        public (string Tag, string? DialerProxy) Tags(int index, string tag, string? dialerProxy)
        {
            return (index == _exitHop && _takesExitTag ? Global.AetherExitNodeTag : tag,
                index == _aetherHop ? null : dialerProxy);
        }

        /// <summary>
        /// Settles <paramref name="outbound" />, built for hop <paramref name="index" />: an Aether outbound learns its
        /// chain, and the Aether hop dials out through the hops on its entry side, nearest first; an Aether outbound
        /// behind another hop, which carries the connection of that hop to its server, passes names on unless its
        /// profile sets a targetStrategy; and the exit-node passes every name the core sends on as it is.
        /// </summary>
        public void Settle(int index, Outbounds4Ray outbound)
        {
            if (_context.Aether.UseOf(outbound) is { } use)
            {
                use.ChainTag = _chainTag;
                if (index == _aetherHop && _exitHop >= 0)
                {
                    use.Exit = AetherExit.Through(_hops.Skip(_exitHop), hop => _context.CustomOutboundContent.GetValueOrDefault(hop.IndexId));
                }
                if (index > 0 && !AetherOutbound.KeepsTargetStrategyBehindAHop(_hops[index]))
                {
                    outbound.targetStrategy = null;
                }
            }
            if (index == _exitHop && _takesExitTag)
            {
                outbound.targetStrategy = null;
            }
        }
    }
}
