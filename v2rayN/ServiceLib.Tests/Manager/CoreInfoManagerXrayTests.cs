namespace ServiceLib.Tests.Manager;

/// <summary>
/// PattN: Xray on Windows runs from its copy p-xray-p.exe beside xray.exe and never as xray.exe, whatever it runs for: a
/// session, a test, a scan, a key run, or a version check (<see cref="CoreInfoManager.RunFileOf" />); before every run the
/// copy is checked against xray.exe and made equal to it but for its name (<see cref="CoreInfoManager.SyncXrayCopy" />).
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
    public async Task TheCopyIsXrayUnderAnotherNameBesideIt()
    {
        var xray = Xray("Xray 26.1.1");

        await CoreInfoManager.XrayCopyOf(xray).Should().BeEqualTo(Copy);
        await Path.GetFileName(Copy).Should().BeEqualTo("p-xray-p.exe");
    }

    [Test]
    public async Task XrayRunsFromItsCopyMadeWhereThereIsNone()
    {
        var xray = Xray("Xray 26.1.1");

        var run = CoreInfoManager.XrayRunFile(xray, out var msg);

        await run.Should().BeEqualTo(Copy);
        await msg.Should().BeEmpty();
        await File.ReadAllText(Copy).Should().BeEqualTo("Xray 26.1.1");
        await File.ReadAllText(xray).Should().BeEqualTo("Xray 26.1.1");
    }

    [Test]
    public async Task AnUpdatedXrayIsCopiedOverTheOldCopy()
    {
        // As once an update replaced xray.exe.
        File.WriteAllText(Copy, "Xray 25.9.11");
        var xray = Xray("Xray 26.1.1");

        await CoreInfoManager.SyncXrayCopy(xray, out var msg).Should().BeTrue();
        await msg.Should().BeEmpty();
        await File.ReadAllText(Copy).Should().BeEqualTo("Xray 26.1.1");
        // And a run, or a version check, runs the new one.
        await CoreInfoManager.XrayRunFile(xray, out _).Should().BeEqualTo(Copy);
        await File.ReadAllText(Copy).Should().BeEqualTo("Xray 26.1.1");
    }

    [Test]
    public async Task ACopyEqualToXrayIsLeftAsItIs()
    {
        var xray = Xray("Xray 26.1.1");
        File.WriteAllText(Copy, "Xray 26.1.1");
        var written = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        File.SetLastWriteTimeUtc(Copy, written);

        await CoreInfoManager.SyncXrayCopy(xray, out _).Should().BeTrue();
        await File.GetLastWriteTimeUtc(Copy).Should().BeEqualTo(written);
    }

    [Test]
    public async Task XrayIsNotRunAtAllWhereNoCopyCanBeMade()
    {
        var xray = Xray("Xray 26.1.1");
        // A folder where the copy would go: no file can be made there, and xray.exe is not run instead.
        Directory.CreateDirectory(Copy);

        await CoreInfoManager.SyncXrayCopy(xray, out var syncFailure).Should().BeFalse();
        await syncFailure.Should().Contain(Copy);
        var run = CoreInfoManager.XrayRunFile(xray, out var msg);
        await run.Should().BeEmpty();
        await msg.Should().Contain(Copy);
    }

    [Test]
    public async Task AnOlderCopyThatRunsIsNotRunAgain()
    {
        // Windows keeps a file that runs, or is open, from being replaced; elsewhere it can be replaced at any time.
        if (!OperatingSystem.IsWindows())
        {
            return;
        }
        File.WriteAllText(Copy, "Xray 25.9.11");
        var xray = Xray("Xray 26.1.1");

        // An Xray runs from the older copy.
        using (new FileStream(Copy, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            // An update says so...
            await CoreInfoManager.SyncXrayCopy(xray, out var syncFailure).Should().BeFalse();
            await syncFailure.Should().Contain(Copy);
            // ... and no other run starts from a copy that differs from xray.exe.
            await CoreInfoManager.XrayRunFile(xray, out var msg).Should().BeEmpty();
            await msg.Should().Contain(Copy);
        }
        await File.ReadAllText(Copy).Should().BeEqualTo("Xray 25.9.11");
        // Once it no longer runs, the next run brings it up to date and runs it.
        await CoreInfoManager.XrayRunFile(xray, out _).Should().BeEqualTo(Copy);
        await File.ReadAllText(Copy).Should().BeEqualTo("Xray 26.1.1");
    }

    [Test]
    public async Task CopiesEqualToXrayRunSideBySide()
    {
        // As a latency test's Xray starts while the session's runs from the same copy.
        var xray = Xray("Xray 26.1.1");
        File.WriteAllText(Copy, "Xray 26.1.1");

        using (new FileStream(Copy, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            await CoreInfoManager.XrayRunFile(xray, out var msg).Should().BeEqualTo(Copy);
            await msg.Should().BeEmpty();
        }
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
