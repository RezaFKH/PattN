using TUnit.Assertions.Enums;

namespace ServiceLib.Tests.Aether;

/// <summary>
/// PattN (design 2.6.4, critiques 15 and 31; PattNG CoreServiceManager.launchCore): what CoreManager.LoadCore does for the
/// Aether core, once the configuration is generated and once Xray started, and the turns its loads and stops take with
/// the stop that follows an Aether core exiting on its own. Every step is a fake that writes down that it ran.
/// </summary>
public class AetherCoreLoadTests
{
    private static readonly AetherCore Warp = new AetherCore(["--masque", "--bind", "127.0.0.1:10819"]).Through(10822);

    /// <summary>Steps that write down what they do; <paramref name="core" /> is the Aether core the configuration needs.</summary>
    private sealed class Steps(AetherCore? core)
    {
        public List<string> Events { get; } = [];
        public string? Missing { get; init; }
        public bool XrayUp { get; set; } = true;
        public bool PortListens { get; init; } = true;

        /// <summary>Xray as it is once the wait for its inbound is over: it may have ended meanwhile.</summary>
        public bool? XrayUpAfterTheWait { get; init; }

        public string? SessionFailure { get; init; }
        public long Generation { get; private set; } = 41;

        public AetherCoreLoadSteps Build()
        {
            return new AetherCoreLoadSteps
            {
                Core = () => core,
                MissingCore = () => Missing,
                NewGeneration = () =>
                {
                    Events.Add("new generation");
                    return ++Generation;
                },
                CancelProbes = () => Log("cancel probes"),
                XrayUp = () => XrayUp,
                WaitForPort = port =>
                {
                    Events.Add($"wait for {port}");
                    if (XrayUpAfterTheWait is { } after)
                    {
                        XrayUp = after;
                    }
                    return Task.FromResult(PortListens);
                },
                StartSession = (started, generation) =>
                {
                    Events.Add($"start aether {generation}");
                    return Task.FromResult(SessionFailure);
                },
                StopCores = () => Log("stop cores"),
                Report = (notify, message) => Log($"report {notify} {message}"),
            };
        }

        private Task Log(string text)
        {
            Events.Add(text);
            return Task.CompletedTask;
        }
    }

    // ---- before the old cores stop

    [Test]
    public async Task ALoadThatNeedsAnAetherCoreCancelsALatencyTestBeforeTheOldCoresStop()
    {
        var steps = new Steps(Warp);

        // A latency test's core may hold the listen port; the cores the load starts are a new generation.
        await (await AetherCoreLoad.BeforeStopAsync(steps.Build())).Should().BeEqualTo(42);
        await steps.Events.Should().BeEquivalentTo(["new generation", "cancel probes"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task AnAetherCoreThatCannotRunKeepsTheCoresThatRun()
    {
        var steps = new Steps(Warp) { Missing = "The Core file (file name: aether) was not found" };

        await (await AetherCoreLoad.BeforeStopAsync(steps.Build())).Should().BeNull();

        // No new generation: the end of the old session still stops the old Xray.
        await steps.Events.Should().BeEquivalentTo(["report True The Core file (file name: aether) was not found"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task AConfigurationWithoutAnAetherProfileStartsAsBefore()
    {
        var steps = new Steps(null) { Missing = "never asked" };

        await (await AetherCoreLoad.BeforeStopAsync(steps.Build())).Should().BeEqualTo(42);
        await (await AetherCoreLoad.AfterXrayAsync(steps.Build(), 42)).Should().BeEqualTo(AetherCoreLoadOutcome.NoCore);

        // No probe of a latency test is cancelled, and nothing waits for an inbound of the core.
        await steps.Events.Should().BeEquivalentTo(["new generation"], CollectionOrdering.Matching);
    }

    // ---- once Xray started

    [Test]
    public async Task TheAetherCoreStartsOnceXraysInboundListens()
    {
        var steps = new Steps(Warp);

        await (await AetherCoreLoad.AfterXrayAsync(steps.Build(), 42)).Should().BeEqualTo(AetherCoreLoadOutcome.Started);

        // Xray's secondary-socks inbound listens before the core is started on it, as a session of the load's generation.
        await steps.Events.Should().BeEquivalentTo(["wait for 10822", "start aether 42"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task TheAetherCoreIsNotStartedWhenXrayIsNotUp()
    {
        // Critique 31: Xray reported why it did not start; the core would only dial a port nobody listens on.
        var steps = new Steps(Warp) { XrayUp = false };

        await (await AetherCoreLoad.AfterXrayAsync(steps.Build(), 42)).Should().BeEqualTo(AetherCoreLoadOutcome.XrayDown);

        await steps.Events.Should().BeEmpty();
    }

    [Test]
    public async Task TheAetherCoreIsNotStartedWhenXrayEndsWhileItWaits()
    {
        // Xray was up a moment after its start and ended before its inbound listened (a port it cannot bind, a wrong
        // password for sudo); a listener of another program on that port does not count either.
        foreach (var listens in new[] { false, true })
        {
            var steps = new Steps(Warp) { XrayUpAfterTheWait = false, PortListens = listens };

            await (await AetherCoreLoad.AfterXrayAsync(steps.Build(), 42)).Should().BeEqualTo(AetherCoreLoadOutcome.XrayDown).Because($"listens: {listens}");

            await steps.Events.Should().BeEquivalentTo(["wait for 10822"], CollectionOrdering.Matching).Because($"listens: {listens}");
        }
    }

    [Test]
    public async Task XrayAndTheAetherCoreRunTogetherOrNotAtAll()
    {
        var steps = new Steps(Warp) { SessionFailure = "The Aether core could not start" };

        await (await AetherCoreLoad.AfterXrayAsync(steps.Build(), 42)).Should().BeEqualTo(AetherCoreLoadOutcome.AetherFailed);

        await steps.Events.Should().BeEquivalentTo(
            ["wait for 10822", "start aether 42", "report True The Aether core could not start", "stop cores"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task TheAetherCoreStartsEvenWhenXraysInboundIsSlowToListen()
    {
        var steps = new Steps(Warp) { PortListens = false };

        await (await AetherCoreLoad.AfterXrayAsync(steps.Build(), 42)).Should().BeEqualTo(AetherCoreLoadOutcome.Started);

        await steps.Events.Should().BeEquivalentTo(["wait for 10822", "start aether 42"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task ACoreThatNamesAnUpstreamOfItsOwnStartsWithoutAWaitForXray()
    {
        // A hand-written --upstream to a proxy elsewhere is no inbound of Xray's.
        var steps = new Steps(new AetherCore(["--masque", "--bind", "127.0.0.1:10819", "--upstream", "socks5://192.0.2.7:1080"]));

        await AetherCoreLoad.AfterXrayAsync(steps.Build(), 42);

        await steps.Events.Should().BeEquivalentTo(["start aether 42"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task TheUpstreamOfACoreIsTheLoopbackPortItNames()
    {
        await AetherCoreLoad.UpstreamPort(Warp).Should().BeEqualTo(10822);
        await AetherCoreLoad.UpstreamPort(new AetherCore(["--upstream", "socks5://localhost:2080"])).Should().BeEqualTo(2080);
        await AetherCoreLoad.UpstreamPort(new AetherCore(["--upstream", "socks5h://user:pass@[::1]:2081"])).Should().BeEqualTo(2081);
        await AetherCoreLoad.UpstreamPort(new AetherCore(["--upstream", "socks5://192.0.2.7:1080"])).Should().BeNull();
        await AetherCoreLoad.UpstreamPort(new AetherCore(["--masque"])).Should().BeNull();
        await AetherCoreLoad.UpstreamPort(new AetherCore(["--upstream", "not a url"])).Should().BeNull();
    }

    [Test]
    public async Task AWaitForAPortEndsOnceItListensOrWhenItsTimeIsUp()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        try
        {
            await (await AetherCoreLoad.WaitForPortAsync(port, TimeSpan.FromSeconds(5))).Should().BeTrue();
        }
        finally
        {
            listener.Stop();
        }
        var waited = Stopwatch.StartNew();
        await (await AetherCoreLoad.WaitForPortAsync(port, TimeSpan.FromMilliseconds(400))).Should().BeFalse();
        await (waited.Elapsed < TimeSpan.FromSeconds(3)).Should().BeTrue();
    }

    // ---- the turns of loads, stops and the end of a session (critique 15)

    [Test]
    public async Task ASessionThatEndsOnItsOwnStopsTheCoresOfItsGeneration()
    {
        var turns = new AetherCoreTurns();
        long generation = 0;
        await turns.RunAsync(() =>
        {
            generation = turns.NewGeneration();
            return Task.CompletedTask;
        });
        var stops = 0;

        await (await turns.EndIfCurrentAsync(generation, () =>
        {
            stops++;
            return Task.CompletedTask;
        })).Should().BeTrue();

        await stops.Should().BeEqualTo(1);
        // Reported twice, it stops once: the stop started a generation of its own.
        await (await turns.EndIfCurrentAsync(generation, () =>
        {
            stops++;
            return Task.CompletedTask;
        })).Should().BeFalse();
        await stops.Should().BeEqualTo(1);
    }

    [Test]
    public async Task ACoreThatDiesWhileAReloadStartsTheNextCoresNeverStopsThem()
    {
        var turns = new AetherCoreTurns();
        long old = 0;
        await turns.RunAsync(() =>
        {
            old = turns.NewGeneration();
            return Task.CompletedTask;
        });
        var reloadStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var xrayUp = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var events = new List<string>();

        // A reload takes its turn: it stops the old cores and is between starting Xray and starting the next Aether core.
        var reload = turns.RunAsync(async () =>
        {
            turns.NewGeneration();
            lock (events)
            {
                events.Add("reload stops the old cores");
            }
            reloadStarted.SetResult();
            await xrayUp.Task;
            lock (events)
            {
                events.Add("reload starts the next aether core");
            }
        });
        await reloadStarted.Task;
        // The old core's end, reported meanwhile, waits for the reload's turn and finds a newer generation then.
        var end = turns.EndIfCurrentAsync(old, () =>
        {
            lock (events)
            {
                events.Add("the end stops the cores");
            }
            return Task.CompletedTask;
        });
        await Task.Delay(100);
        await end.IsCompleted.Should().BeFalse();
        xrayUp.SetResult();
        await reload;

        await (await end).Should().BeFalse();
        await events.Should().BeEquivalentTo(["reload stops the old cores", "reload starts the next aether core"], CollectionOrdering.Matching);
    }

    [Test]
    public async Task AReloadThatFailsBeforeItReplacesTheCoresLeavesTheirEndToStopThem()
    {
        var turns = new AetherCoreTurns();
        long old = 0;
        await turns.RunAsync(() =>
        {
            old = turns.NewGeneration();
            return Task.CompletedTask;
        });
        // A configuration that cannot be generated starts no generation: the old Xray still runs, without its core.
        await turns.RunAsync(() => Task.CompletedTask);
        var stopped = false;

        await (await turns.EndIfCurrentAsync(old, () =>
        {
            stopped = true;
            return Task.CompletedTask;
        })).Should().BeTrue();
        await stopped.Should().BeTrue();
    }

    [Test]
    public async Task AStopOnRequestOwnsTheCoresAsWell()
    {
        var turns = new AetherCoreTurns();
        long session = 0;
        await turns.RunAsync(() =>
        {
            session = turns.NewGeneration();
            return Task.CompletedTask;
        });
        // CoreStop: a new generation, then the stop.
        await turns.RunAsync(() =>
        {
            turns.NewGeneration();
            return Task.CompletedTask;
        });

        await (await turns.EndIfCurrentAsync(session, () => Task.CompletedTask)).Should().BeFalse();
    }
}
