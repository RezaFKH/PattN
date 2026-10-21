namespace ServiceLib.Aether;

/// <summary>
/// What CoreManager.LoadCore does for the Aether core, through <see cref="AetherCoreLoad.BeforeStopAsync" /> and
/// <see cref="AetherCoreLoad.AfterXrayAsync" />; fakes in tests.
/// </summary>
public sealed class AetherCoreLoadSteps
{
    /// <summary>The Aether core the configuration needs (CoreConfigContext.Aether.Core), read once it was generated.</summary>
    public required Func<AetherCore?> Core { get; init; }

    /// <summary>Why the Aether core cannot run, as when its program is missing; null when it can.</summary>
    public required Func<string?> MissingCore { get; init; }

    /// <summary>Starts a new generation of the cores (<see cref="AetherCoreTurns.NewGeneration" />) and returns it.</summary>
    public required Func<long> NewGeneration { get; init; }

    /// <summary>Cancels a latency test's core, which may hold the Aether listen port (AetherCoreManager.CancelProbesAsync).</summary>
    public required Func<Task> CancelProbes { get; init; }

    /// <summary>Whether Xray runs.</summary>
    public required Func<bool> XrayUp { get; init; }

    /// <summary>Waits, for a short while, until a loopback port accepts connections.</summary>
    public required Func<int, Task<bool>> WaitForPort { get; init; }

    /// <summary>Starts the Aether session of a generation; the localized reason when it does not start.</summary>
    public required Func<AetherCore, long, Task<string?>> StartSession { get; init; }

    /// <summary>Stops the cores that run, the Aether session first.</summary>
    public required Func<Task> StopCores { get; init; }

    /// <summary>Tells the user (true: also as a notification) and the message view.</summary>
    public required Func<bool, string, Task> Report { get; init; }
}

/// <summary>How the Aether part of a load went, see <see cref="AetherCoreLoad.AfterXrayAsync" />.</summary>
public enum AetherCoreLoadOutcome
{
    /// <summary>The configuration needs no Aether core.</summary>
    NoCore,

    /// <summary>Xray is not up, so no Aether core was started either; the rest of the load goes on as before.</summary>
    XrayDown,

    /// <summary>The Aether core did not start, and Xray was stopped with it; the load ends there.</summary>
    AetherFailed,

    Started,
}

/// <summary>
/// PattN: the Aether part of CoreManager.LoadCore (design 2.6.4, PattNG CoreServiceManager.launchCore), in two steps that
/// LoadCore takes among its own lines, so that the order is tested without processes. Once the configuration is
/// generated, <see cref="BeforeStopAsync" />: a configuration whose Aether core cannot run leaves the cores that run alone,
/// and a latency test's core, which may hold the Aether listen port, is cancelled before the old cores stop. Once Xray
/// started, <see cref="AfterXrayAsync" />: the Aether core dials out through Xray's secondary-socks inbound, so it starts
/// once Xray runs and that inbound listens, and never when Xray did not start or is gone by then. Xray and the Aether core
/// run together or not at all: a core that does not start stops Xray as well.
/// </summary>
public static class AetherCoreLoad
{
    /// <summary>How long the start of an Aether core waits for Xray's inbound it dials out through to listen.</summary>
    public static readonly TimeSpan UpstreamWait = TimeSpan.FromSeconds(5);

    private static readonly TimeSpan PortPoll = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// What follows the generation of the configuration, before the old cores stop: null, after telling why, when the
    /// configuration needs an Aether core that cannot run (the cores that run keep running, and the generation stays, so
    /// that the end of the old session still stops the old Xray); otherwise the generation of the cores the load starts,
    /// with a latency test's core cancelled when the configuration needs an Aether core.
    /// </summary>
    public static async Task<long?> BeforeStopAsync(AetherCoreLoadSteps steps)
    {
        var core = steps.Core();
        if (core != null && steps.MissingCore() is { } missing)
        {
            await steps.Report(true, missing);
            return null;
        }
        var generation = steps.NewGeneration();
        if (core != null)
        {
            await steps.CancelProbes();
        }
        return generation;
    }

    /// <summary>
    /// What follows the start of Xray: the session of <paramref name="generation" /> on the Aether core the configuration
    /// needs, once Xray's inbound it dials out through listens (for <see cref="UpstreamWait" /> at most). No core starts
    /// when Xray is not up, before the wait or after it (critique 31): Xray reported why, and the core would only dial a
    /// port nobody listens on. A core that does not start is reported, and stops Xray with it.
    /// </summary>
    public static async Task<AetherCoreLoadOutcome> AfterXrayAsync(AetherCoreLoadSteps steps, long generation)
    {
        if (steps.Core() is not { } core)
        {
            return AetherCoreLoadOutcome.NoCore;
        }
        if (!steps.XrayUp())
        {
            Logging.SaveLog("CoreManager: Xray did not start, so the Aether core is not started");
            return AetherCoreLoadOutcome.XrayDown;
        }
        if (UpstreamPort(core) is { } upstream)
        {
            var listens = await steps.WaitForPort(upstream);
            // Xray may end a moment after it was seen up (a port it cannot bind, a wrong password for sudo), and a
            // listener of another program on that port answers the wait all the same.
            if (!steps.XrayUp())
            {
                Logging.SaveLog("CoreManager: Xray ended while the Aether core waited for it, so the Aether core is not started");
                return AetherCoreLoadOutcome.XrayDown;
            }
            if (!listens)
            {
                Logging.SaveLog($"CoreManager: nothing listens on {upstream}, which the Aether core dials out through; it starts all the same");
            }
        }
        var failure = await steps.StartSession(core, generation);
        if (failure != null)
        {
            await steps.Report(true, failure);
            await steps.StopCores();
            return AetherCoreLoadOutcome.AetherFailed;
        }
        return AetherCoreLoadOutcome.Started;
    }

    /// <summary>
    /// The loopback port the core dials out through, which its --upstream names (socks5://127.0.0.1:port, as
    /// <see cref="AetherCore.Through" /> writes it); null when it names none, or a proxy elsewhere.
    /// </summary>
    public static int? UpstreamPort(AetherCore core)
    {
        var upstream = AetherArguments.ValueAfter(core.Arguments, AetherArguments.Upstream);
        if (upstream == null || !Uri.TryCreate(upstream, UriKind.Absolute, out var uri) || uri.Port <= 0)
        {
            return null;
        }
        var host = uri.Host.Trim('[', ']');
        var loopback = host.Equals("localhost", StringComparison.OrdinalIgnoreCase)
                       || (IPAddress.TryParse(host, out var address) && IPAddress.IsLoopback(address));
        return loopback ? uri.Port : null;
    }

    /// <summary>
    /// Why the Aether core cannot run here: its program is not in bin/aether (the message every missing core gets), or
    /// cannot be run; null when it can.
    /// </summary>
    public static string? MissingCoreMessage()
    {
        if (AetherBinaries.IsCoreAvailable())
        {
            return null;
        }
        var info = CoreInfoManager.Instance.GetCoreInfo(ECoreType.aether);
        return CoreInfoManager.Instance.GetCoreExecFile(info, out var message).IsNullOrEmpty() && message.IsNotEmpty()
            ? message
            : ResUI.MsgAetherCoreCannotStart;
    }

    /// <summary>
    /// Waits until the loopback <paramref name="port" /> accepts a connection, for at most <paramref name="timeout" />:
    /// a bounded wait while a process comes up. False when the time is up.
    /// </summary>
    public static async Task<bool> WaitForPortAsync(int port, TimeSpan timeout, CancellationToken ct = default)
    {
        var deadline = Stopwatch.StartNew();
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                using var client = new TcpClient();
                using var attempt = CancellationTokenSource.CreateLinkedTokenSource(ct);
                attempt.CancelAfter(AetherCoreManager.ProbeTimeout);
                await client.ConnectAsync(Global.Loopback, port, attempt.Token).ConfigureAwait(false);
                return true;
            }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested)
            {
                // That attempt took too long.
            }
            catch (SocketException)
            {
                // Nothing listens yet.
            }
            if (deadline.Elapsed + PortPoll >= timeout)
            {
                return false;
            }
            await Task.Delay(PortPoll, ct).ConfigureAwait(false);
        }
    }

    /// <summary><see cref="WaitForPortAsync(int, TimeSpan, CancellationToken)" /> for <see cref="UpstreamWait" />.</summary>
    public static Task<bool> WaitForPortAsync(int port)
    {
        return WaitForPortAsync(port, UpstreamWait);
    }
}

/// <summary>
/// PattN (critique 15): the turns CoreManager's loads and stops take, and the stop that follows an Aether core that exits on
/// its own, which takes its turn with them. Each load that replaces the cores, and each stop, starts a new generation; the
/// session started by a load carries its generation, and its end stops the cores only while that generation is still the
/// one that runs: a core that dies while a reload starts the next cores never stops them. A load that fails before it
/// replaces anything keeps the generation, so that the end of the old session still stops the old Xray.
/// </summary>
public sealed class AetherCoreTurns
{
    private readonly SemaphoreSlim _turn = new(1, 1);
    private long _generation;

    /// <summary>The generation of the cores that run now.</summary>
    public long Generation => Interlocked.Read(ref _generation);

    /// <summary>Runs <paramref name="action" />, a load or a stop, in its turn.</summary>
    public async Task RunAsync(Func<Task> action)
    {
        await _turn.WaitAsync().ConfigureAwait(false);
        try
        {
            await action().ConfigureAwait(false);
        }
        finally
        {
            _turn.Release();
        }
    }

    /// <summary>Starts a new generation, from inside a turn, as the cores are replaced or stopped; returns it.</summary>
    public long NewGeneration()
    {
        return Interlocked.Increment(ref _generation);
    }

    /// <summary>
    /// Runs <paramref name="stop" /> in its turn, as a new generation, when <paramref name="generation" /> is still the
    /// generation of the cores; true when it ran, false when a load or a stop began since.
    /// </summary>
    public async Task<bool> EndIfCurrentAsync(long generation, Func<Task> stop)
    {
        await _turn.WaitAsync().ConfigureAwait(false);
        try
        {
            if (generation != Generation)
            {
                return false;
            }
            NewGeneration();
            await stop().ConfigureAwait(false);
            return true;
        }
        finally
        {
            _turn.Release();
        }
    }
}
