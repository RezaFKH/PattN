using System.Formats.Tar;
using System.IO.Compression;

namespace ServiceLib.Aether;

/// <summary>
/// The programs of the Aether core in bin/aether (PattNG AetherCoreManager binary, psiphonBinary and transportBinary,
/// and isSupported, isPsiphonSupported and isTorTransportsSupported), and the unpacking of a release archive of the core
/// into that folder. PattNG ships the three programs in its APK; PattN downloads them from patterniha/Aether's releases
/// on the check-update page, and its release archives bundle them.
/// </summary>
public static class AetherBinaries
{
    /// <summary>The core, which every Aether profile runs on.</summary>
    public const string CoreName = "aether";

    /// <summary>The Psiphon client the core runs for a profile with Psiphon.</summary>
    public const string PsiphonName = "psiphon-tunnel-core";

    /// <summary>The pluggable transport Tor's bridges run through.</summary>
    public const string LyrebirdName = "lyrebird";

    /// <summary>The three programs, the core first.</summary>
    public static IReadOnlyList<string> Names { get; } = [CoreName, PsiphonName, LyrebirdName];

    /// <summary>bin/aether, the folder of <see cref="ECoreType.aether" />.</summary>
    public static string Folder => Utils.GetBinPath("", nameof(ECoreType.aether));

    /// <summary>bin/aether/aether[.exe].</summary>
    public static string CoreFile => FileIn(Folder, CoreName);

    /// <summary>bin/aether/psiphon-tunnel-core[.exe].</summary>
    public static string PsiphonFile => FileIn(Folder, PsiphonName);

    /// <summary>bin/aether/lyrebird[.exe].</summary>
    public static string LyrebirdFile => FileIn(Folder, LyrebirdName);

    /// <summary>Whether the core is there to run (PattNG isSupported).</summary>
    public static bool IsCoreAvailable() => IsRunnable(CoreFile);

    /// <summary>Whether the Psiphon client is there to run; without it a profile with Psiphon cannot connect (PattNG isPsiphonSupported).</summary>
    public static bool IsPsiphonAvailable() => IsRunnable(PsiphonFile);

    /// <summary>Whether lyrebird is there to run; without it Tor has no bridges where it is blocked (PattNG isTorTransportsSupported).</summary>
    public static bool IsLyrebirdAvailable() => IsRunnable(LyrebirdFile);

    /// <summary>The file of the program <paramref name="name" /> in <paramref name="folder" />: name.exe on Windows.</summary>
    public static string FileIn(string folder, string name) => Path.Combine(folder, Utils.GetExeName(name));

    /// <summary>
    /// The full paths of those of the three programs that are in <paramref name="folder" />, the core first. A routing
    /// rule of the TUN sends what they dial out directly: a core whose command names an upstream of its own dials out
    /// itself, and so do the helpers a command leaves without one, which must not loop back into the TUN.
    /// </summary>
    public static List<string> ExistingFiles(string folder)
    {
        return Names.Select(name => FileIn(folder, name)).Where(File.Exists).Select(Path.GetFullPath).ToList();
    }

    /// <summary>
    /// Whether <paramref name="file" /> can be run (PattNG File.canExecute): it exists and, outside Windows, has an
    /// execute bit, without which neither PattN nor the core can start it.
    /// </summary>
    public static bool IsRunnable(string file)
    {
        try
        {
            if (!File.Exists(file))
            {
                return false;
            }
            if (OperatingSystem.IsWindows())
            {
                return true;
            }
            const UnixFileMode execute = UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute;
            return (File.GetUnixFileMode(file) & execute) != 0;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>
    /// Outside Windows, gives each of the three programs in <paramref name="folder" /> that is there its execute bits,
    /// at start and after an update: without them the core cannot start a helper, nor PattN the core.
    /// </summary>
    public static async Task SetExecutableAsync(string folder)
    {
        if (!Utils.IsNonWindows())
        {
            return;
        }
        foreach (var name in Names)
        {
            var file = Path.Combine(folder, name);
            if (File.Exists(file))
            {
                await Utils.SetLinuxChmod(file);
            }
        }
    }

    /// <summary>
    /// Unpacks a release archive of the core into <paramref name="folder" />, flat: aether[.exe], and lyrebird and
    /// psiphon-tunnel-core out of the archive's pt/ folder, all three side by side; the core looks for its helpers
    /// beside itself as well as in pt/. An archive whose name holds .tar.gz is read as a gzip-compressed tar, any other
    /// as a zip, as the check-update page reads the archives of every core. Folders, links and macOS's AppleDouble files
    /// ("._name", which an archive made on a Mac can carry beside each file) are left out. A file already in the folder
    /// is replaced, and no other file of the folder is touched.
    /// </summary>
    /// <returns>The names of the files written, in the order of the archive.</returns>
    /// <exception cref="InvalidDataException">The archive is not a zip, or not a gzip-compressed tar.</exception>
    /// <exception cref="IOException">A file could not be written, as when a running core holds it on Windows.</exception>
    public static List<string> Extract(string archive, string folder)
    {
        Directory.CreateDirectory(folder);
        var written = new List<string>();
        if (archive.Contains(".tar.gz", StringComparison.OrdinalIgnoreCase))
        {
            using var file = File.OpenRead(archive);
            using var gzip = new GZipStream(file, CompressionMode.Decompress);
            using var tar = new TarReader(gzip);
            while (tar.GetNextEntry() is { } entry)
            {
                if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile)
                    || FlatName(entry.Name) is not { } name)
                {
                    continue;
                }
                entry.ExtractToFile(Path.Combine(folder, name), overwrite: true);
                written.Add(name);
            }
        }
        else
        {
            using var zip = ZipFile.OpenRead(archive);
            foreach (var entry in zip.Entries)
            {
                if (FlatName(entry.FullName) is not { } name)
                {
                    continue;
                }
                entry.ExtractToFile(Path.Combine(folder, name), overwrite: true);
                written.Add(name);
            }
        }
        return written;
    }

    /// <summary>
    /// The name an entry of an archive is unpacked to: the last part of its path, whether the archive separates the
    /// parts with '/' or, as a zip made by Windows PowerShell does, with '\'; null for a folder, an AppleDouble file or a
    /// name no file can have, so that no entry is ever written outside the folder.
    /// </summary>
    private static string? FlatName(string path)
    {
        var name = path.Replace('\\', '/');
        name = name[(name.LastIndexOf('/') + 1)..];
        if (name.Length == 0
            || name is "." or ".."
            || name.StartsWith("._", StringComparison.Ordinal)
            || name.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0)
        {
            return null;
        }
        return name;
    }
}
