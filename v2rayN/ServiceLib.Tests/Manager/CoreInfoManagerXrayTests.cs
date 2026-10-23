namespace ServiceLib.Tests.Manager;

/// <summary>
/// PattN: Xray on Windows runs from its copy p-xray-p.exe beside xray.exe and never as xray.exe, whatever it runs for: a
/// session, a test, a scan, a key run, or a version check (<see cref="CoreInfoManager.RunFileOf" />).
/// </summary>
public class CoreInfoManagerXrayTests : IDisposable
{
    // A folder under the temp path for this test alone, removed after it: the bin/xray of an install.
    private readonly string _root = Directory.CreateTempSubdirectory("pattn-xray-run-").FullName;

    public void Dispose()
    {
        Directory.Delete(_root, recursive: true);
    }

    private string Copy => Path.Combine(_root, CoreInfoManager.XrayAliasExeName);

    private string Xray(string content)
    {
        var path = Path.Combine(_root, "xray.exe");
        File.WriteAllText(path, content);
        return path;
    }

    [Test]
    public async Task XrayRunsFromItsCopyMadeBesideIt()
    {
        var xray = Xray("Xray 26.1.1");

        var run = CoreInfoManager.XrayRunFile(xray, out var msg);

        await run.Should().BeEqualTo(Copy);
        await msg.Should().BeEmpty();
        await File.ReadAllText(Copy).Should().BeEqualTo("Xray 26.1.1");
        await File.ReadAllText(xray).Should().BeEqualTo("Xray 26.1.1");
    }

    [Test]
    public async Task TheCopyFollowsXrayWhenItIsUpdated()
    {
        File.WriteAllText(Copy, "Xray 25.9.11");
        var xray = Xray("Xray 26.1.1");

        await CoreInfoManager.XrayRunFile(xray, out _).Should().BeEqualTo(Copy);
        await File.ReadAllText(Copy).Should().BeEqualTo("Xray 26.1.1");
    }

    [Test]
    public async Task XrayIsNotRunAtAllWhereNoCopyCanBeMade()
    {
        var xray = Xray("Xray 26.1.1");
        // A folder where the copy would go: no file can be made there, and xray.exe is not run instead.
        Directory.CreateDirectory(Copy);

        var run = CoreInfoManager.XrayRunFile(xray, out var msg);

        await run.Should().BeEmpty();
        await msg.Should().Contain(Copy);
    }

    [Test]
    public async Task ACopyThatRunsIsUsedAsItIs()
    {
        // Windows keeps a file that runs, or is open, from being replaced; elsewhere it can be replaced at any time.
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        File.WriteAllText(Copy, "Xray 25.9.11");
        var xray = Xray("Xray 26.1.1");

        using (new FileStream(Copy, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            await CoreInfoManager.XrayRunFile(xray, out var msg).Should().BeEqualTo(Copy);
            await msg.Should().BeEmpty();
        }
        await File.ReadAllText(Copy).Should().BeEqualTo("Xray 25.9.11");
    }

    [Test]
    public async Task OnlyXrayOnWindowsRunsFromACopy()
    {
        var xray = Xray("Xray 26.1.1");

        var run = CoreInfoManager.RunFileOf(new CoreInfo { CoreType = ECoreType.Xray }, xray, out var msg);

        await run.Should().BeEqualTo(OperatingSystem.IsWindows() ? Copy : xray);
        await msg.Should().BeEmpty();

        var singBox = Path.Combine(_root, "sing-box.exe");
        File.WriteAllText(singBox, "sing-box 1.13.0");
        await CoreInfoManager.RunFileOf(new CoreInfo { CoreType = ECoreType.sing_box }, singBox, out _).Should().BeEqualTo(singBox);
    }
}
