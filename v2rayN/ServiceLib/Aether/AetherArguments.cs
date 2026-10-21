using System.Globalization;

namespace ServiceLib.Aether;

/// <summary>
/// The arguments an Aether core is started with (PattNG AetherCoreManager.kt): those a profile's settings give, and the
/// reading of a command line, word by word, the way the core reads it. Nothing here starts a process or touches a file.
/// </summary>
public static class AetherArguments
{
    /// <summary>The option that names Psiphon's own listener.</summary>
    public const string PsiphonBind = "--psiphon-bind";

    /// <summary>The option that names Tor's own listener.</summary>
    public const string TorBind = "--tor-bind";

    /// <summary>The option that names the proxy the core dials out through.</summary>
    public const string Upstream = "--upstream";

    /// <summary>The core's flag naming the file of server entries the Psiphon client starts with.</summary>
    public const string PsiphonServerEntries = "--psiphon-server-entries";

    /// <summary>The word a command names the app's own list by; the real file takes its place when the core starts.</summary>
    public const string ShippedList = "shipped-list";

    /// <summary>Environment variable that tells the core where the Psiphon client is; it looks for it under other names otherwise.</summary>
    public const string PsiphonBinEnv = "AETHER_PSIPHON_BIN";

    /// <summary>Environment variable naming the directory the Psiphon client keeps its datastore in.</summary>
    public const string PsiphonDirEnv = "AETHER_PSIPHON_DIR";

    /// <summary>The level the core logs at unless told otherwise; it writes its info lines there.</summary>
    public const string DefaultLogLevel = "info";

    /// <summary>
    /// The server name the MASQUE handshakes put in their ClientHello unless a profile names another; the core's own
    /// default as well. The HTTP host of the CONNECT request stays the core's (PattNG AppConfig.AETHER_MASQUE_SNI).
    /// </summary>
    public const string DefaultMasqueSni = "www.cloudflare.com";

    /// <summary>Where the core asks for the ECH key unless a profile names another resolver (PattNG AppConfig.AETHER_ECH_DNS).</summary>
    public const string DefaultEchDns = "udp://1.1.1.1";

    /// <summary>The domain whose ECH key the core takes unless a profile names another (PattNG AppConfig.AETHER_ECH_DOMAIN).</summary>
    public const string DefaultEchDomain = "cloudflare-ech.com";

    /// <summary>The carriers as <see cref="PathOf" /> names them, beside the names of <see cref="AetherProtocol" />.</summary>
    private const string TorName = "TOR";

    private const string PsiphonName = "PSIPHON";

    /// <summary>The levels at which the core writes its info lines, the ready word among them.</summary>
    private static readonly HashSet<string> InfoLevels = ["info", "debug", "trace"];

    /// <summary>The values of --wiw-peers and --mim-peers that ask for a scan instead of naming hops, as the core reads them.</summary>
    private static readonly HashSet<string> ScanKeywords = ["auto", "scan", "none", "off", "0"];

    /// <summary>
    /// The text of a setting as the value of an option of the core: trimmed, and null when it is blank or starts with
    /// '-'. No value of these settings starts so, and one that did would read as an option of its own wherever the app
    /// looks options up word by word: a link carrying dns=--upstream would leave the core without the upstream the app
    /// gives it, so that it dialled out around Xray. Trimmed by Kotlin's whitespace, as PattNG trims it (see
    /// <see cref="KotlinText" />): the core would keep the separators U+001C to U+001F, and trims U+0085 itself.
    /// </summary>
    public static string? SettingValue(string? value)
    {
        var text = KotlinText.TrimOrNull(value);
        return string.IsNullOrEmpty(text) || text.StartsWith('-') ? null : text;
    }

    /// <summary>
    /// Whether a tunnel over MASQUE runs over HTTP/2: chosen so, or dialled through Tor or Psiphon around it, which
    /// carry TCP alone, so that the core takes HTTP/2 whatever <paramref name="transport" /> says.
    /// </summary>
    public static bool MasqueOverHttp2(AetherProtocol protocol, AetherTransport transport, AetherTor tor, AetherPsiphon psiphon)
    {
        return protocol.OverMasque
               && (transport == AetherTransport.Http2 || tor == AetherTor.Reverse || psiphon == AetherPsiphon.Reverse);
    }

    /// <summary>True when a core on <paramref name="arguments" /> reaches WARP through Tor or Psiphon, which then has to come up before anything else can.</summary>
    public static bool ReachesWarpThroughCarrier(IReadOnlyList<string> arguments)
    {
        return TorModeOf(arguments) == AetherTor.Reverse || PsiphonModeOf(arguments) == AetherPsiphon.Reverse;
    }

    /// <summary>
    /// The arguments of the core of <paramref name="profile" /> on the Aether listen port <paramref name="port" />,
    /// for a scan when <paramref name="scan" />, at <paramref name="logLevel" />. A profile's endpoint is its
    /// Address/Port, Port 0 meaning none.
    /// </summary>
    public static List<string> Build(ProfileItem profile, int port, bool scan = false, string logLevel = DefaultLogLevel)
    {
        var extra = profile.GetProtocolExtra();
        var protocol = AetherProtocol.FromString(extra.AetherProtocol);
        // A scan looks for WARP endpoints from where the session will look: a carrier around the tunnel
        // stays, since the session reaches WARP from its exit, while one inside the tunnel has no part in it.
        var tor = AetherTor.FromString(extra.AetherTor);
        if (scan && tor != AetherTor.Reverse)
        {
            tor = AetherTor.Off;
        }
        var psiphon = AetherPsiphon.FromString(extra.AetherPsiphon);
        if (scan && psiphon != AetherPsiphon.Reverse)
        {
            psiphon = AetherPsiphon.Off;
        }
        // The listener the app dials takes [port]: Psiphon's or Tor's when one of them runs inside the
        // tunnel and is what the app reaches, the tunnel's own otherwise. Every other listener takes the
        // ports after it, in this order: the tunnel's own, then Tor's, then Psiphon's. Psiphon around the
        // tunnel is the exception: nothing of the app dials its listener and the core takes the port
        // Psiphon reports, so an ephemeral port keeps a scan core from colliding with the session's.
        // Tor around the tunnel gets a real port, since the core dials the address Tor was told to
        // listen on. (long: no port the app passes runs past an int, and none may throw here.)
        var dialsPsiphon = psiphon == AetherPsiphon.Chain;
        var dialsTor = tor == AetherTor.Chain && !dialsPsiphon;
        var next = (long)port + 1;
        var own = dialsPsiphon || dialsTor ? next++ : port;
        long? torBind = null;
        if (tor == AetherTor.Chain)
        {
            torBind = dialsTor ? port : next++;
        }
        else if (tor == AetherTor.Reverse)
        {
            torBind = next++;
        }
        long? psiphonBind = null;
        if (psiphon == AetherPsiphon.Chain)
        {
            psiphonBind = dialsPsiphon ? port : next++;
        }
        else if (psiphon == AetherPsiphon.Reverse)
        {
            psiphonBind = 0;
        }

        var arguments = new List<string> { "--bind", LoopbackAddress(own) };
        if (psiphon != AetherPsiphon.Only && tor != AetherTor.Only)
        {
            arguments.AddRange(["--protocol", protocol.Core]);
            // gool has meant WireGuard over MASQUE since aether 2.3.0; WARP-in-WARP is the classic gool, asked for
            // by name rather than left to the hop settings that select it as well.
            if (protocol == AetherProtocol.Gool)
            {
                arguments.Add("--gool-classic");
            }
            arguments.AddRange(["--scan", AetherScanMode.FromString(extra.AetherScanMode).Type]);
            // Automatic obfuscation is the core's own choice per protocol, so nothing is said about it; MASQUE over
            // HTTP/2 takes none at all, since obfuscation shapes the UDP of WireGuard and HTTP/3 alone.
            var transport = AetherTransport.FromString(extra.AetherTransport);
            var obfuscation = AetherObfuscation.FromString(extra.AetherObfuscation);
            if (obfuscation != AetherObfuscation.Auto && !MasqueOverHttp2(protocol, transport, tor, psiphon))
            {
                arguments.AddRange(["--noize", obfuscation.Type]);
            }
            arguments.AddRange(["--ip", AetherIpVersion.FromString(extra.AetherIpVersion).Type]);
            AddOption(arguments, "--dns", SettingValue(extra.AetherDns));
            // A scan keeps the exit rule as well, so that it ends on an endpoint the session will accept.
            AddOption(arguments, "--exit-loc", SettingValue(extra.AetherExitLoc));

            // The server name the MASQUE handshakes put in their ClientHello, on either carrier and both hops, the
            // default named as well, so that the command shows what is sent; the HTTP host stays the core's.
            if (protocol.OverMasque)
            {
                arguments.AddRange(["--masque-sni", SettingValue(extra.AetherMasqueSni) ?? DefaultMasqueSni]);
            }
            if (protocol.OverMasque && transport == AetherTransport.Http2)
            {
                arguments.Add("--h2");
                // The ClientHello of the MASQUE handshake, and of the calls to the WARP API the core makes for a
                // key it does not have; without the flag the core sends both whole.
                if (extra.AetherFragment == true)
                {
                    arguments.Add("--fragment");
                    AddOption(arguments, "--fragment-size", AetherRange.Parse(extra.AetherFragmentSize, AetherRange.FragmentSize)?.ToString());
                    AddOption(arguments, "--fragment-delay", AetherRange.Parse(extra.AetherFragmentDelay, AetherRange.FragmentDelay)?.ToString());
                }
            }
            // Encrypted Client Hello hides the server name of the MASQUE handshake, on either carrier and both hops,
            // with the key of the HTTPS record of the ECH domain, asked of the ECH resolver.
            if (protocol.OverMasque && extra.AetherEch == true)
            {
                arguments.AddRange(["--ech", "auto"]);
                arguments.AddRange(["--ech-dns", SettingValue(extra.AetherEchDns) ?? DefaultEchDns]);
                arguments.AddRange(["--ech-domain", SettingValue(extra.AetherEchDomain) ?? DefaultEchDomain]);
            }
            // The ClientHello of the MASQUE handshakes, and of the WARP API calls and the ECH key lookup the core makes:
            // over HTTP/3, which carries TLS 1.3 alone, only its GREASE shows.
            if (protocol.OverMasque)
            {
                arguments.AddRange(AetherFingerprint.FromString(extra.AetherFingerprint).Arguments);
            }

            if (protocol == AetherProtocol.WgOverMasque)
            {
                // The outer hop is a MASQUE gateway, which a scan looks for afresh. The inner one is the WireGuard
                // endpoint dialled inside the tunnel, the one WARP assigned the key unless one is named; no scan looks
                // for it, so a scan keeps the profile's own and finds a gateway that works with it.
                AddOption(arguments, "--peer", scan ? null : AetherEndpoint.Parse(extra.AetherWiwOuter)?.ToString());
                AddOption(arguments, "--gool-peer", AetherEndpoint.Parse(extra.AetherWiwInner)?.ToString());
            }
            else if (protocol.TwoHops)
            {
                var hop = protocol == AetherProtocol.Mim ? "--mim" : "--wiw";
                var outer = scan ? null : AetherEndpoint.Parse(extra.AetherWiwOuter);
                var inner = scan ? null : AetherEndpoint.Parse(extra.AetherWiwInner);
                AddOption(arguments, $"{hop}-outer", outer?.ToString());
                AddOption(arguments, $"{hop}-inner", inner?.ToString());
                if (outer == null && inner == null)
                {
                    arguments.Add($"{hop}-scan");
                }
            }
            else if (!scan)
            {
                // Port 0 is no port: the core scans.
                var endpointPort = profile.Port == 0 ? null : profile.Port.ToString(CultureInfo.InvariantCulture);
                AddOption(arguments, "--peer", AetherEndpoint.Of(profile.Address, endpointPort)?.ToString());
            }

            arguments.Add(scan ? "--no-quick-reconnect" : "--quick-reconnect");
        }

        if (tor == AetherTor.Chain)
        {
            arguments.Add("--tor");
        }
        else if (tor == AetherTor.Reverse)
        {
            arguments.Add("--tor-reverse");
        }
        else if (tor == AetherTor.Only)
        {
            arguments.Add("--tor-only");
        }
        if (torBind != null)
        {
            arguments.AddRange([TorBind, LoopbackAddress(torBind.Value)]);
        }
        if (tor != AetherTor.Off)
        {
            // Told nothing, the core tries Tor plainly and turns to fetched bridges where Tor is blocked.
            var bridges = AetherTorBridges.FromString(extra.AetherTorBridges);
            if (bridges == AetherTorBridges.First)
            {
                arguments.Add("--tor-bridges");
            }
            else if (bridges == AetherTorBridges.Never)
            {
                arguments.Add("--no-tor-bridges");
            }
            else if (bridges == AetherTorBridges.Own)
            {
                foreach (var line in AetherFmt.BridgeLines(extra.AetherTorBridgeLines))
                {
                    AddOption(arguments, "--tor-bridge", SettingValue(line));
                }
            }
            // Where fetched bridges come from; with the profile's own lines, or none at all, nothing is fetched.
            if (bridges == AetherTorBridges.Auto || bridges == AetherTorBridges.First)
            {
                var relays = AetherTorRelays.FromString(extra.AetherTorRelays);
                if (relays != AetherTorRelays.Auto)
                {
                    arguments.AddRange(["--tor-relays", relays.Type]);
                }
            }
        }

        if (psiphon == AetherPsiphon.Chain)
        {
            arguments.Add("--psiphon");
        }
        else if (psiphon == AetherPsiphon.Reverse)
        {
            arguments.Add("--psiphon-reverse");
        }
        else if (psiphon == AetherPsiphon.Only)
        {
            arguments.Add("--psiphon-only");
        }
        if (psiphonBind != null)
        {
            arguments.AddRange([PsiphonBind, LoopbackAddress(psiphonBind.Value)]);
        }
        if (psiphon != AetherPsiphon.Off)
        {
            var shape = AetherPsiphonMode.FromString(extra.AetherPsiphonMode);
            arguments.AddRange(["--psiphon-mode", shape.Type]);
            // The CDN lists feed the fronted transports alone, which the direct shape never uses; the
            // server names count only beside an IP list of one's own, since the built-in list comes whole.
            var cdnIps = shape != AetherPsiphonMode.Direct ? SettingValue(extra.AetherPsiphonCdnIps) : null;
            AddOption(arguments, "--psiphon-cdn-ips", cdnIps);
            if (cdnIps != null)
            {
                AddOption(arguments, "--psiphon-cdn-sni", SettingValue(extra.AetherPsiphonCdnSni));
            }
            // Which of the edge lists built into Psiphon the fronting scan tries; beside addresses of one's own, after them.
            if (shape != AetherPsiphonMode.Direct)
            {
                AddOption(arguments, "--psiphon-cdn-sets", AetherPsiphonCdnSet.Join(AetherPsiphonCdnSet.Parse(extra.AetherPsiphonCdnSets)));
            }
            AddOption(arguments, "--psiphon-region", SettingValue(extra.AetherPsiphonRegion));
            // The bundled list, unless the profile wants Psiphon to fetch a fresh one before it dials anything.
            if (extra.AetherPsiphonBundledList != false)
            {
                arguments.AddRange([PsiphonServerEntries, ShippedList]);
            }
        }
        arguments.AddRange(["--log-level", logLevel]);
        return arguments;
    }

    /// <summary>
    /// Maps the app's core log level setting onto the levels the core accepts. Only the session follows the setting:
    /// scans and key renewals keep the default because they read info lines.
    /// </summary>
    public static string CoreLogLevel(string? appLevel)
    {
        switch (appLevel?.ToLowerInvariant())
        {
            case "debug":
                return "debug";

            case "info":
                return "info";

            case "warning":
            case "warn":
                return "warn";

            case "error":
            case "none":
                return "error";

            default:
                return DefaultLogLevel;
        }
    }

    /// <summary>
    /// The level the session core on <paramref name="arguments" /> runs at for the app setting
    /// <paramref name="appLevel" /> (the pure part of PattNG AetherCoreManager.start): <see cref="CoreLogLevel" />,
    /// raised to the default where readiness needs the ready word, which is an info line.
    /// </summary>
    public static string SessionLogLevel(IReadOnlyList<string> arguments, string? appLevel)
    {
        var logLevel = CoreLogLevel(appLevel);
        // The ready word is an info line; a quieter setting must not leave a Psiphon session waiting for it.
        return ReadyNeedsWord(arguments) && !InfoLevels.Contains(logLevel) ? DefaultLogLevel : logLevel;
    }

    /// <summary><paramref name="arguments" /> at <paramref name="logLevel" />, unless they name a level of their own, as a hand-written command may.</summary>
    public static List<string> WithLogLevel(IReadOnlyList<string> arguments, string logLevel)
    {
        var result = arguments.ToList();
        if (!arguments.Contains("--log-level") && !arguments.Contains("--verbose"))
        {
            result.AddRange(["--log-level", logLevel]);
        }
        return result;
    }

    /// <summary>
    /// <paramref name="arguments" /> at a level that writes the core's info lines, which a run that waits for one of
    /// them needs: as they are, unless they name a quieter level, which gives way to the default.
    /// </summary>
    public static List<string> WithInfoLines(IReadOnlyList<string> arguments)
    {
        if (ShowsInfo(arguments))
        {
            return arguments.ToList();
        }
        var result = WithoutOption(arguments, "--log-level");
        result.AddRange(["--log-level", DefaultLogLevel]);
        return result;
    }

    /// <summary>True when a core started with <paramref name="arguments" /> writes its info lines, at the level named or at the default.</summary>
    public static bool ShowsInfo(IReadOnlyList<string> arguments)
    {
        return arguments.Contains("--verbose") || InfoLevels.Contains(ValueAfter(arguments, "--log-level") ?? DefaultLogLevel);
    }

    /// <summary>
    /// True when the listener the app dials is Psiphon's, inside the tunnel or alone: it answers the greeting before it
    /// carries anything, so readiness needs the core's word as well.
    /// </summary>
    public static bool ReadyNeedsWord(IReadOnlyList<string> arguments)
    {
        var psiphon = PsiphonModeOf(arguments);
        return psiphon == AetherPsiphon.Chain || psiphon == AetherPsiphon.Only;
    }

    /// <summary>
    /// <paramref name="arguments" /> as the core is started with them: the word <see cref="ShippedList" /> after
    /// <see cref="PsiphonServerEntries" /> gives way to the full path of <paramref name="entries" />, the app's
    /// unpacked list, or the flag goes when there is no such file. A file of the command's own is left as written.
    /// </summary>
    public static List<string> WithShippedList(IReadOnlyList<string> arguments, string? entries)
    {
        var result = arguments.ToList();
        var at = result.IndexOf(PsiphonServerEntries);
        if (at < 0 || at + 1 >= result.Count || result[at + 1] != ShippedList)
        {
            return result;
        }
        if (entries == null)
        {
            result.RemoveRange(at, 2);
        }
        else
        {
            result[at + 1] = Path.GetFullPath(entries);
        }
        return result;
    }

    /// <summary>
    /// The arguments of a core of its own, a scan, a key renewal or a latency test: <paramref name="arguments" />
    /// dialling out through the exit on <paramref name="exitPort" />. An upstream they name, as a configuration exported
    /// from a session names the session's Xray, gives way to it. (PattNG writes this as AetherCore.through on the
    /// arguments without --upstream, which then always adds the upstream.)
    /// </summary>
    public static List<string> StandaloneArguments(IReadOnlyList<string> arguments, int exitPort)
    {
        var result = WithoutOption(arguments, Upstream);
        result.AddRange([Upstream, $"socks5://{LoopbackAddress(exitPort)}"]);
        return result;
    }

    /// <summary>
    /// <paramref name="arguments" /> without the listeners, the log level and the upstream proxy: what tells one tunnel
    /// from another. The session's core dials out through Xray and its profile does not say so.
    /// </summary>
    public static List<string> TunnelArguments(IReadOnlyList<string> arguments)
    {
        IReadOnlyList<string> result = arguments;
        foreach (var flag in new[] { "--log-level", "--bind", TorBind, PsiphonBind, Upstream })
        {
            result = WithoutOption(result, flag);
        }
        return result.ToList();
    }

    /// <summary><paramref name="arguments" /> without every <paramref name="flag" /> and the value after it.</summary>
    public static List<string> WithoutOption(IReadOnlyList<string> arguments, string flag)
    {
        var kept = new List<string>();
        var index = 0;
        while (index < arguments.Count)
        {
            if (arguments[index] == flag)
            {
                index += 2;
            }
            else
            {
                kept.Add(arguments[index++]);
            }
        }
        return kept;
    }

    /// <summary>
    /// <paramref name="arguments" /> with the listener <paramref name="flag" /> names on the loopback port
    /// <paramref name="port" />, in place of whatever they named for it.
    /// </summary>
    public static List<string> WithListener(IReadOnlyList<string> arguments, string flag, int port)
    {
        var result = WithoutOption(arguments, flag);
        result.AddRange([flag, LoopbackAddress(port)]);
        return result;
    }

    /// <summary>
    /// The option naming the listener the app dials: Psiphon's when Psiphon runs inside the tunnel, Tor's when Tor
    /// does, the core's own otherwise. Both inside at once is refused by the editor; a command written that way is
    /// dialled on Psiphon's.
    /// </summary>
    public static string ListenerFlagOf(IReadOnlyList<string> arguments)
    {
        if (PsiphonModeOf(arguments) == AetherPsiphon.Chain)
        {
            return PsiphonBind;
        }
        if (TorModeOf(arguments) == AetherTor.Chain)
        {
            return TorBind;
        }
        return "--bind";
    }

    /// <summary>Where Tor stands in the tunnel <paramref name="argv" /> runs, read the way the core reads it: the last mode flag wins.</summary>
    public static AetherTor TorModeOf(IReadOnlyList<string> argv)
    {
        var mode = AetherTor.Off;
        foreach (var word in argv)
        {
            switch (word)
            {
                case "--tor":
                    mode = AetherTor.Chain;
                    break;

                case "--tor-reverse":
                    mode = AetherTor.Reverse;
                    break;

                case "--tor-only":
                    mode = AetherTor.Only;
                    break;
            }
        }
        return mode;
    }

    /// <summary>Where Psiphon stands in the tunnel <paramref name="argv" /> runs, read the way the core reads it: the last mode flag wins.</summary>
    public static AetherPsiphon PsiphonModeOf(IReadOnlyList<string> argv)
    {
        var mode = AetherPsiphon.Off;
        foreach (var word in argv)
        {
            switch (word)
            {
                case "--psiphon":
                    mode = AetherPsiphon.Chain;
                    break;

                case "--psiphon-reverse":
                    mode = AetherPsiphon.Reverse;
                    break;

                case "--psiphon-only":
                    mode = AetherPsiphon.Only;
                    break;
            }
        }
        return mode;
    }

    /// <summary>
    /// The tunnel <paramref name="argv" /> runs, as the names of its parts from the outside in: a carrier around the
    /// tunnel, the WARP protocol, which <paramref name="label" /> names (PattNG's enum names, such as WG_OVER_MASQUE,
    /// unless given), a carrier inside it. A carrier alone is the whole tunnel, and Tor alone comes before Psiphon
    /// alone, as the core runs it before it looks at Psiphon.
    /// </summary>
    public static List<string> PathOf(IReadOnlyList<string> argv, Func<AetherProtocol, string>? label = null)
    {
        var tor = TorModeOf(argv);
        var psiphon = PsiphonModeOf(argv);
        if (tor == AetherTor.Only)
        {
            return [TorName];
        }
        if (psiphon == AetherPsiphon.Only)
        {
            return [PsiphonName];
        }
        var path = new List<string>();
        if (tor == AetherTor.Reverse)
        {
            path.Add(TorName);
        }
        if (psiphon == AetherPsiphon.Reverse)
        {
            path.Add(PsiphonName);
        }
        path.Add((label ?? NameOf)(ProtocolOf(argv)));
        if (psiphon == AetherPsiphon.Chain)
        {
            path.Add(PsiphonName);
        }
        if (tor == AetherTor.Chain)
        {
            path.Add(TorName);
        }
        return path;
    }

    /// <summary>
    /// Whether what the app sends through the tunnel <paramref name="argv" /> runs leaves it through WARP, the last part
    /// of <see cref="PathOf" />: not through Tor or Psiphon, which come last when they run inside the tunnel or are the
    /// whole of it.
    /// </summary>
    public static bool LeavesThroughWarp(IReadOnlyList<string> argv)
    {
        return LeavesThroughWarp(TorModeOf(argv), PsiphonModeOf(argv));
    }

    /// <summary><see cref="LeavesThroughWarp(IReadOnlyList{string})" /> with Tor standing at <paramref name="tor" /> and Psiphon at <paramref name="psiphon" />.</summary>
    public static bool LeavesThroughWarp(AetherTor tor, AetherPsiphon psiphon)
    {
        return (tor == AetherTor.Off || tor == AetherTor.Reverse)
               && (psiphon == AetherPsiphon.Off || psiphon == AetherPsiphon.Reverse);
    }

    /// <summary>The port of the core's own listener, null when <paramref name="argv" /> names none.</summary>
    public static int? BindPortOf(IReadOnlyList<string> argv)
    {
        return PortAfter(argv, "--bind");
    }

    /// <summary>The address of the listener the app dials, see <see cref="ListenerFlagOf" />; null when <paramref name="argv" /> names none.</summary>
    public static string? ListenerAddressOf(IReadOnlyList<string> argv)
    {
        return ValueAfter(argv, ListenerFlagOf(argv));
    }

    /// <summary>The port of the listener the app dials, null when <paramref name="argv" /> names none.</summary>
    public static int? ListenerPortOf(IReadOnlyList<string> argv)
    {
        return PortOf(ListenerAddressOf(argv));
    }

    /// <summary>The port of the address after <paramref name="flag" />, null when there is none or it cannot be read.</summary>
    public static int? PortAfter(IReadOnlyList<string> argv, string flag)
    {
        return PortOf(ValueAfter(argv, flag));
    }

    /// <summary>
    /// The protocol <paramref name="argv" /> selects, read the way the core reads it: the last of --protocol and the
    /// protocol flags wins, a hop named without any of them selects the two-hop protocol it belongs to, warp-in-warp
    /// before masque-in-masque, and nothing at all is masque. Gool is WireGuard over MASQUE unless --gool-classic or a
    /// warp-in-warp hop setting, a scan of the hops included, makes it WARP-in-WARP, the classic gool, wherever they
    /// stand.
    /// </summary>
    public static AetherProtocol ProtocolOf(IReadOnlyList<string> argv)
    {
        AetherProtocol? chosen = null;
        var classicMode = false;
        // Each hop setting is a variable of the core's environment, so the last value given counts, a blank one included.
        var hops = new Dictionary<HopSetting, string>();
        for (var index = 0; index < argv.Count; index++)
        {
            var value = index + 1 < argv.Count ? argv[index + 1] : null;
            switch (argv[index])
            {
                case "--protocol":
                    if (value != null)
                    {
                        chosen = ProtocolNamed(value);
                    }
                    break;

                case "--masque":
                    chosen = AetherProtocol.Masque;
                    break;

                case "--wg":
                case "--wireguard":
                case "--warp":
                    chosen = AetherProtocol.WireGuard;
                    break;

                case "--gool":
                case "--wiw":
                case "--gool-peer":
                    chosen = AetherProtocol.WgOverMasque;
                    break;

                case "--gool-classic":
                    chosen = AetherProtocol.WgOverMasque;
                    classicMode = true;
                    break;

                case "--mim":
                case "--masque-in-masque":
                    chosen = AetherProtocol.Mim;
                    break;

                case "--wiw-outer":
                case "--gool-outer":
                case "--outer-peer":
                    SetHop(hops, HopSetting.WiwOuter, value);
                    break;

                case "--wiw-inner":
                case "--gool-inner":
                case "--inner-peer":
                    SetHop(hops, HopSetting.WiwInner, value);
                    break;

                case "--wiw-peers":
                case "--gool-peers":
                    SetHop(hops, HopSetting.WiwPeers, value);
                    break;

                case "--wiw-scan":
                case "--gool-scan":
                    hops[HopSetting.WiwPeers] = "auto";
                    break;

                case "--mim-outer":
                    SetHop(hops, HopSetting.MimOuter, value);
                    break;

                case "--mim-inner":
                    SetHop(hops, HopSetting.MimInner, value);
                    break;

                case "--mim-peers":
                    SetHop(hops, HopSetting.MimPeers, value);
                    break;

                case "--mim-scan":
                    hops[HopSetting.MimPeers] = "auto";
                    break;
            }
        }
        // A blank value sets nothing for the core; a list of peers names hops unless it asks for a scan. Trimmed as the
        // core trims a variable of its environment (Rust's str::trim, whose whitespace is .NET's), not by Kotlin's
        // whitespace as PattNG does: the command is read the way the core reads it.
        string? Given(HopSetting setting)
        {
            var text = hops.TryGetValue(setting, out var hop) ? hop.Trim() : null;
            return string.IsNullOrEmpty(text) ? null : text;
        }
        bool Pinned(HopSetting outer, HopSetting inner, HopSetting peers)
        {
            return Given(outer) != null || Given(inner) != null || NamesHops(Given(peers));
        }
        var classicGool = classicMode
                          || Given(HopSetting.WiwOuter) != null
                          || Given(HopSetting.WiwInner) != null
                          || Given(HopSetting.WiwPeers) != null;
        if (chosen == AetherProtocol.WgOverMasque)
        {
            return classicGool ? AetherProtocol.Gool : AetherProtocol.WgOverMasque;
        }
        if (chosen != null)
        {
            return chosen;
        }
        if (Pinned(HopSetting.WiwOuter, HopSetting.WiwInner, HopSetting.WiwPeers))
        {
            return AetherProtocol.Gool;
        }
        if (Pinned(HopSetting.MimOuter, HopSetting.MimInner, HopSetting.MimPeers))
        {
            return AetherProtocol.Mim;
        }
        return AetherProtocol.Masque;
    }

    /// <summary>The value after the last <paramref name="flag" /> in <paramref name="argv" />; the last one is the one the core keeps.</summary>
    public static string? ValueAfter(IReadOnlyList<string> argv, string flag)
    {
        for (var index = argv.Count - 1; index >= 0; index--)
        {
            if (argv[index] == flag)
            {
                return index + 1 < argv.Count ? argv[index + 1] : null;
            }
        }
        return null;
    }

    /// <summary>The hop settings <see cref="ProtocolOf" /> reads, each the variable of the core's environment its flags set.</summary>
    private enum HopSetting
    {
        WiwOuter,
        WiwInner,
        WiwPeers,
        MimOuter,
        MimInner,
        MimPeers,
    }

    private static void SetHop(Dictionary<HopSetting, string> hops, HopSetting setting, string? value)
    {
        if (value != null)
        {
            hops[setting] = value;
        }
    }

    /// <summary>
    /// The protocol the core selects for <paramref name="name" /> after --protocol, under any of the names it accepts;
    /// gool is WireGuard over MASQUE until <see cref="ProtocolOf" /> finds what makes it the classic one. Trimmed as the
    /// core's Protocol::parse trims it (Rust's whitespace, which is .NET's), not by Kotlin's whitespace.
    /// </summary>
    private static AetherProtocol ProtocolNamed(string name)
    {
        switch (name.Trim().ToLowerInvariant())
        {
            case "wg":
            case "wireguard":
                return AetherProtocol.WireGuard;

            case "gool":
            case "wiw":
            case "warp-in-warp":
            case "warpinwarp":
                return AetherProtocol.WgOverMasque;

            case "mim":
            case "m2":
            case "masque-in-masque":
            case "masqueinmasque":
                return AetherProtocol.Mim;

            default:
                return AetherProtocol.Masque;
        }
    }

    /// <summary>Whether a value of --wiw-peers or --mim-peers names hops rather than asking for a scan, as the core reads it.</summary>
    private static bool NamesHops(string? value)
    {
        return value != null && !ScanKeywords.Contains(value.ToLowerInvariant());
    }

    /// <summary>The name PattNG's AetherProtocol enum gives <paramref name="protocol" />, the default label of <see cref="PathOf" />.</summary>
    private static string NameOf(AetherProtocol protocol)
    {
        if (protocol == AetherProtocol.Masque)
        {
            return "MASQUE";
        }
        if (protocol == AetherProtocol.WireGuard)
        {
            return "WIREGUARD";
        }
        if (protocol == AetherProtocol.Gool)
        {
            return "GOOL";
        }
        if (protocol == AetherProtocol.Mim)
        {
            return "MIM";
        }
        return "WG_OVER_MASQUE";
    }

    /// <summary>The port of <paramref name="address" />, the text after its last ':'; null when there is none or it is no number.</summary>
    private static int? PortOf(string? address)
    {
        if (address == null)
        {
            return null;
        }
        var separator = address.LastIndexOf(':');
        return separator < 0 ? null : AetherDigits.ToIntOrNull(address.Substring(separator + 1));
    }

    /// <summary><paramref name="flag" /> and <paramref name="value" />, when there is a value.</summary>
    private static void AddOption(List<string> arguments, string flag, string? value)
    {
        if (value != null)
        {
            arguments.AddRange([flag, value]);
        }
    }

    private static string LoopbackAddress(long port)
    {
        return string.Create(CultureInfo.InvariantCulture, $"{Global.Loopback}:{port}");
    }
}
