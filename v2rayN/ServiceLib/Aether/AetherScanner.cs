namespace ServiceLib.Aether;

/// <summary>What a scan found: the endpoint, and the inner hop's of a two-hop tunnel that names one.</summary>
public sealed record AetherScanResult(AetherEndpoint Endpoint, AetherEndpoint? InnerHop = null);

/// <summary>
/// Reading the endpoint a scan of the core found out of its output (PattNG core/AetherScanner.kt).
/// </summary>
public static partial class AetherScanner
{
    /// <summary>How long a scan may take.</summary>
    public static readonly TimeSpan ScanTimeout = TimeSpan.FromMinutes(8);

    /// <summary>The source label of a scan's output.</summary>
    public const string Source = "aether-scan";

    // PattNG's \S is Java's: anything but ASCII white space, where .NET's also leaves out the other spaces of Unicode.
    private const string NonSpace = @"[^ \t\n\x0B\f\r]";

    /// <summary>
    /// What ends a scan, line by line. Without an exit rule, the line that names the endpoint. With one, the core names
    /// its endpoint before it checks the exit behind it and looks again when the rule refuses it, so the endpoint named
    /// last counts only once the core has accepted its exit. Masque-in-masque and WireGuard over MASQUE say they are ready
    /// after that check, so their line stands on its own either way.
    /// </summary>
    public static Func<string, AetherScanResult?> Matcher(AetherProtocol protocol, bool exitRuled)
    {
        if (!exitRuled || protocol == AetherProtocol.Mim || protocol == AetherProtocol.WgOverMasque)
        {
            return line => Parse(protocol, line);
        }
        AetherScanResult? named = null;
        return line =>
        {
            var found = Parse(protocol, line);
            if (found != null)
            {
                named = found;
                return null;
            }
            if (ExitAcceptedRegex().IsMatch(line))
            {
                return named;
            }
            if (ExitRejectedRegex().IsMatch(line))
            {
                named = null;
            }
            return null;
        };
    }

    /// <summary>The endpoint <paramref name="line" /> names for a tunnel of <paramref name="protocol" />; null when it names none.</summary>
    public static AetherScanResult? Parse(AetherProtocol protocol, string line)
    {
        if (protocol == AetherProtocol.Gool)
        {
            return HopsOf(GoolHopsRegex(), line);
        }
        if (protocol == AetherProtocol.Mim)
        {
            return HopsOf(MimHopsRegex(), line);
        }
        if (protocol == AetherProtocol.Masque)
        {
            return OneHopOf(MasqueGatewayRegex(), line);
        }
        if (protocol == AetherProtocol.WireGuard)
        {
            return OneHopOf(WireGuardEndpointRegex(), line);
        }
        // Once the whole tunnel carries, the gateway alone: the WireGuard endpoint inside it is the profile's, which the scan kept.
        return OneHopOf(GoolOverMasqueReadyRegex(), line);
    }

    private static AetherScanResult? OneHopOf(Regex regex, string line)
    {
        var match = regex.Match(line);
        if (!match.Success)
        {
            return null;
        }
        var endpoint = EndpointOf(match.Groups[1].Value);
        return endpoint == null ? null : new AetherScanResult(endpoint);
    }

    private static AetherScanResult? HopsOf(Regex hops, string line)
    {
        var match = hops.Match(line);
        if (!match.Success)
        {
            return null;
        }
        var outer = EndpointOf(match.Groups[1].Value);
        var inner = EndpointOf(match.Groups[2].Value);
        return outer != null && inner != null ? new AetherScanResult(outer, inner) : null;
    }

    /// <summary>The endpoint the core wrote, which its log may write as an IPv6 address and a port without brackets.</summary>
    private static AetherEndpoint? EndpointOf(string text)
    {
        var endpoint = AetherEndpoint.Parse(text);
        if (endpoint != null)
        {
            return endpoint;
        }
        var separator = text.LastIndexOf(':');
        if (separator <= 0)
        {
            return null;
        }
        return AetherEndpoint.Of(text.Substring(0, separator), text.Substring(separator + 1));
    }

    [GeneratedRegex("selected MASQUE gateway (" + NonSpace + "+)", RegexOptions.CultureInvariant)]
    private static partial Regex MasqueGatewayRegex();

    [GeneratedRegex("selected WireGuard endpoint (" + NonSpace + "+)", RegexOptions.CultureInvariant)]
    private static partial Regex WireGuardEndpointRegex();

    [GeneratedRegex("using cloudflare edge (" + NonSpace + @"+) \(outer\) and (" + NonSpace + @"+) \(inner\)", RegexOptions.CultureInvariant)]
    private static partial Regex GoolHopsRegex();

    [GeneratedRegex("masque-in-masque ready: (" + NonSpace + @"+) \(outer\) and (" + NonSpace + @"+) \(inner\)", RegexOptions.CultureInvariant)]
    private static partial Regex MimHopsRegex();

    [GeneratedRegex("gool ready: masque (" + NonSpace + "+) carries wireguard (" + NonSpace + "+)", RegexOptions.CultureInvariant)]
    private static partial Regex GoolOverMasqueReadyRegex();

    [GeneratedRegex("exit location " + NonSpace + "+ accepted", RegexOptions.CultureInvariant)]
    private static partial Regex ExitAcceptedRegex();

    [GeneratedRegex("exit location " + NonSpace + "+ rejected", RegexOptions.CultureInvariant)]
    private static partial Regex ExitRejectedRegex();
}
