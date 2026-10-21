namespace ServiceLib.Aether;

/// <summary>
/// The loopback ports of the Aether core (PattNG AetherCoreManager.kt): the listen port every core listens on, whatever
/// its profile, and every Aether outbound dials, unless a command written by hand names another; the two ports after it,
/// which Tor and Psiphon may take; and the third, Xray's secondary-socks inbound, which the core of a session dials out
/// through.
/// </summary>
public static class AetherPorts
{
    /// <summary>The Aether listen port unless the setting names another.</summary>
    public const int DefaultListenPort = 10819;

    /// <summary>
    /// How far above the listen port the secondary-socks inbound is: past the two after it that Psiphon and Tor may take.
    /// </summary>
    public const int SecondaryOffset = 3;

    /// <summary>Ports below this one are the system's; a program cannot listen there.</summary>
    public const int FirstListenPort = 1024;

    /// <summary>The highest Aether listen port: the three ports after it are the core's as well.</summary>
    public const int LastListenPort = 65535 - SecondaryOffset;

    /// <summary>
    /// The Aether listen port the setting <paramref name="text" /> names: a port a program can listen on, with the three
    /// ports after it ports as well; the default port for anything else.
    /// </summary>
    public static int ListenPortOf(string? text)
    {
        return ListenPortOf(AetherDigits.ToIntOrNull(text?.Trim()));
    }

    /// <summary>
    /// <see cref="ListenPortOf(string?)" /> for a setting stored as a number: a value that is no such port gives way to
    /// the default.
    /// </summary>
    public static int ListenPortOf(int? port)
    {
        return port is >= FirstListenPort and <= LastListenPort ? port.Value : DefaultListenPort;
    }

    /// <summary>The port of the secondary-socks inbound for the Aether listen port <paramref name="listenPort" />.</summary>
    public static int SecondarySocksPortOf(int listenPort)
    {
        return listenPort + SecondaryOffset;
    }

    /// <summary>
    /// Why <paramref name="text" /> cannot be the Aether listen port beside local ports on
    /// <paramref name="localPorts" />; null when it can. The caller decides which of its ports count.
    /// </summary>
    public static AetherListenPortProblem? ListenPortProblem(string text, IEnumerable<int> localPorts)
    {
        var port = AetherDigits.ToIntOrNull(text.Trim());
        if (port is not (>= FirstListenPort and <= LastListenPort))
        {
            return AetherListenPortProblem.NotAPort;
        }
        var ports = localPorts.ToHashSet();
        for (var offset = 0; offset <= SecondaryOffset; offset++)
        {
            if (ports.Contains(port.Value + offset))
            {
                return AetherListenPortProblem.LocalProxy;
            }
        }
        return null;
    }

    /// <summary>
    /// Whether <paramref name="port" /> is one the core of the Aether listen port <paramref name="listenPort" /> may
    /// take: the listen port or one of the three after it.
    /// </summary>
    public static bool IsReserved(int port, int listenPort)
    {
        var offset = (long)port - listenPort;
        return offset is >= 0 and <= SecondaryOffset;
    }

    /// <summary>
    /// The port a scan of <paramref name="profile" /> binds: none, since nothing dials it, unless Tor around the
    /// tunnel comes along, whose own listener follows the tunnel's and needs a real port, because the core dials the
    /// address Tor was told to listen on. Opens a socket to find one.
    /// </summary>
    public static int ScanPort(ProfileItem profile)
    {
        if (AetherTor.FromString(profile.GetProtocolExtra().AetherTor) != AetherTor.Reverse)
        {
            return 0;
        }
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
        finally
        {
            listener.Stop();
        }
    }
}

/// <summary>Why a value cannot be the Aether listen port.</summary>
public enum AetherListenPortProblem
{
    /// <summary>No port a program can listen on, with the three ports after it ports as well.</summary>
    NotAPort,

    /// <summary>The port, or one of the three after it, which the core takes as well, is a local port of the app.</summary>
    LocalProxy,
}
