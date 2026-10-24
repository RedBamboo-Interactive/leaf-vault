namespace Leaf.Vault.Store;

/// <summary>
/// Write-then-rename. The new content is written to a unique temp file in the same
/// directory, flushed to disk, then moved over the target (MoveFileEx REPLACE_EXISTING on
/// NTFS), so a reader or a crash sees either the old file or the new one, never a mix.
/// </summary>
internal static class AtomicFile
{
    public const string TempSuffix = ".tmp";

    public static void Write(string path, ReadOnlySpan<byte> content, bool overwrite = true)
    {
        var temp = $"{path}.{Guid.NewGuid():N}{TempSuffix}";
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
            {
                stream.Write(content);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temp, path, overwrite);
        }
        finally
        {
            if (File.Exists(temp)) File.Delete(temp);
        }
    }

    /// <summary>Removes temp files left by a crash between write and rename.</summary>
    public static void RemoveStale(string directory, string fileName)
    {
        foreach (var stale in Directory.EnumerateFiles(directory, fileName + ".*" + TempSuffix))
            File.Delete(stale);
    }
}
