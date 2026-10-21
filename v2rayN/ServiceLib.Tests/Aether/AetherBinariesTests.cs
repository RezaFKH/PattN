using System.Formats.Tar;
using System.IO.Compression;
using TUnit.Assertions.Enums;

namespace ServiceLib.Tests.Aether;

/// <summary>
/// PattN: the programs of the Aether core in bin/aether, and the unpacking of the fork's release archives (a zip on
/// Windows, a gzip-compressed tar elsewhere, both holding aether and a pt/ folder with lyrebird and psiphon-tunnel-core).
/// </summary>
public class AetherBinariesTests : IDisposable
{
    // A folder under the temp path for this test alone, removed after it; the archives' bin/aether is a folder in it.
    private readonly string _root = Directory.CreateTempSubdirectory("pattn-aether-binaries-").FullName;

    public void Dispose()
    {
        Directory.Delete(_root, recursive: true);
    }

    private string Folder => Path.Combine(_root, "bin", "aether");

    private string Read(string name) => File.ReadAllText(Path.Combine(Folder, name));

    /// <summary>Every file and folder under <see cref="_root" />, as paths relative to it with '/'.</summary>
    private List<string> Tree() =>
        Directory.EnumerateFileSystemEntries(_root, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(_root, path).Replace('\\', '/'))
            .Order(StringComparer.Ordinal)
            .ToList();

    private string Zip(params (string Name, string? Text)[] entries)
    {
        var path = Path.Combine(_root, "aether-windows-x86_64.zip");
        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);
        foreach (var (name, text) in entries)
        {
            var entry = zip.CreateEntry(name);
            if (text != null)
            {
                using var writer = new StreamWriter(entry.Open());
                writer.Write(text);
            }
        }
        return path;
    }

    private string TarGz(params TarEntry[] entries)
    {
        var path = Path.Combine(_root, "aether-linux-x86_64-musl.tar.gz");
        using var file = File.Create(path);
        using var gzip = new GZipStream(file, CompressionLevel.Fastest);
        using var tar = new TarWriter(gzip, TarEntryFormat.Pax);
        foreach (var entry in entries)
        {
            tar.WriteEntry(entry);
        }
        return path;
    }

    private static PaxTarEntry TarFile(string name, string text) =>
        new(TarEntryType.RegularFile, name) { DataStream = new MemoryStream(Encoding.UTF8.GetBytes(text)) };

    [Test]
    public async Task TheThreeProgramsAreTheCoreAndItsTwoHelpers()
    {
        await AetherBinaries.Names.Should().BeEquivalentTo(["aether", "psiphon-tunnel-core", "lyrebird"], CollectionOrdering.Matching);
        var exe = OperatingSystem.IsWindows() ? ".exe" : "";
        await Path.GetFileName(AetherBinaries.CoreFile).Should().BeEqualTo("aether" + exe);
        await Path.GetFileName(AetherBinaries.PsiphonFile).Should().BeEqualTo("psiphon-tunnel-core" + exe);
        await Path.GetFileName(AetherBinaries.LyrebirdFile).Should().BeEqualTo("lyrebird" + exe);
        await AetherBinaries.CoreFile.Should().BeEqualTo(Path.Combine(Utils.GetBinPath("", "aether"), "aether" + exe));
        await Path.GetDirectoryName(AetherBinaries.PsiphonFile).Should().BeEqualTo(AetherBinaries.Folder);
        await Path.GetDirectoryName(AetherBinaries.LyrebirdFile).Should().BeEqualTo(AetherBinaries.Folder);
    }

    [Test]
    public async Task TheWindowsZipIsUnpackedFlatWithoutAppleDoubleFiles()
    {
        Directory.CreateDirectory(Folder);
        File.WriteAllText(Path.Combine(Folder, "aether.exe"), "old core");
        File.WriteAllText(Path.Combine(Folder, "keep.txt"), "not the archive's");
        var archive = Zip(
            ("aether.exe", "core"),
            ("pt/", null),
            ("pt/lyrebird.exe", "lyrebird"),
            // Windows PowerShell's Compress-Archive separates the parts of a name with '\'.
            ("pt\\psiphon-tunnel-core.exe", "psiphon"),
            ("run-aether.bat", "bat"),
            ("._aether.exe", "apple double"),
            ("__MACOSX/pt/._lyrebird.exe", "apple double"));

        var written = AetherBinaries.Extract(archive, Folder);

        await written.Should().BeEquivalentTo(
            ["aether.exe", "lyrebird.exe", "psiphon-tunnel-core.exe", "run-aether.bat"], CollectionOrdering.Matching);
        await Read("aether.exe").Should().BeEqualTo("core");
        await Read("lyrebird.exe").Should().BeEqualTo("lyrebird");
        await Read("psiphon-tunnel-core.exe").Should().BeEqualTo("psiphon");
        await Read("keep.txt").Should().BeEqualTo("not the archive's");
        await Tree().Should().BeEquivalentTo(
            [
                "aether-windows-x86_64.zip", "bin", "bin/aether", "bin/aether/aether.exe", "bin/aether/keep.txt",
                "bin/aether/lyrebird.exe", "bin/aether/psiphon-tunnel-core.exe", "bin/aether/run-aether.bat",
            ],
            CollectionOrdering.Matching);
    }

    [Test]
    public async Task TheTarballIsUnpackedFlatWithoutAppleDoubleFilesLinksOrFolders()
    {
        var archive = TarGz(
            // bsdtar on a Mac writes an AppleDouble file before each file with extended attributes.
            TarFile("._aether", "apple double"),
            TarFile("aether", "core"),
            new PaxTarEntry(TarEntryType.Directory, "pt/"),
            TarFile("pt/._lyrebird", "apple double"),
            TarFile("pt/lyrebird", "lyrebird"),
            TarFile("pt/psiphon-tunnel-core", "psiphon"),
            new PaxTarEntry(TarEntryType.SymbolicLink, "pt/link") { LinkName = "../../outside" },
            // A name that climbs out of the folder is unpacked into it all the same.
            TarFile("../escaped", "escaped"));

        var written = AetherBinaries.Extract(archive, Folder);

        await written.Should().BeEquivalentTo(["aether", "lyrebird", "psiphon-tunnel-core", "escaped"], CollectionOrdering.Matching);
        await Read("aether").Should().BeEqualTo("core");
        await Read("lyrebird").Should().BeEqualTo("lyrebird");
        await Read("psiphon-tunnel-core").Should().BeEqualTo("psiphon");
        await Tree().Should().BeEquivalentTo(
            [
                "aether-linux-x86_64-musl.tar.gz", "bin", "bin/aether", "bin/aether/aether", "bin/aether/escaped",
                "bin/aether/lyrebird", "bin/aether/psiphon-tunnel-core",
            ],
            CollectionOrdering.Matching);
    }

    [Test]
    public async Task ADownloadThatIsNoArchiveIsRefused()
    {
        var zip = Path.Combine(_root, "aether-windows-x86_64.zip");
        var tarGz = Path.Combine(_root, "aether-linux-x86_64-musl.tar.gz");
        File.WriteAllText(zip, "<html>rate limited</html>");
        File.WriteAllText(tarGz, "<html>rate limited</html>");

        Action unzip = () => AetherBinaries.Extract(zip, Folder);
        Action untar = () => AetherBinaries.Extract(tarGz, Folder);

        await unzip.Should().Throw<InvalidDataException>();
        await untar.Should().Throw<InvalidDataException>();
        await Directory.EnumerateFileSystemEntries(Folder).Any().Should().BeFalse();
    }

    [Test]
    public async Task AProgramRunsWhenItIsThereAndOutsideWindowsHasAnExecuteBit()
    {
        var file = Path.Combine(_root, "aether");
        await AetherBinaries.IsRunnable(file).Should().BeFalse();

        File.WriteAllText(file, "core");
        if (OperatingSystem.IsWindows())
        {
            await AetherBinaries.IsRunnable(file).Should().BeTrue();
            return;
        }

        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        await AetherBinaries.IsRunnable(file).Should().BeFalse();
        File.SetUnixFileMode(file, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        await AetherBinaries.IsRunnable(file).Should().BeTrue();
    }

    [Test]
    public async Task OutsideWindowsTheThreeProgramsGetTheirExecuteBits()
    {
        Directory.CreateDirectory(Folder);
        foreach (var name in AetherBinaries.Names)
        {
            File.WriteAllText(Path.Combine(Folder, name), name);
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(Path.Combine(Folder, name), UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
        File.WriteAllText(Path.Combine(Folder, "run-aether.bat"), "bat");

        await AetherBinaries.SetExecutableAsync(Folder);

        foreach (var name in AetherBinaries.Names)
        {
            await AetherBinaries.IsRunnable(Path.Combine(Folder, name)).Should().BeTrue();
        }
        if (!OperatingSystem.IsWindows())
        {
            await AetherBinaries.IsRunnable(Path.Combine(Folder, "run-aether.bat")).Should().BeFalse();
        }
    }
}
