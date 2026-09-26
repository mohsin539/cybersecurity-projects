using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Text;

namespace ProxyCore.Security;

/// <summary>
/// Secret vault for proxy credentials. AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC),
/// key derived from DPAPI-protected master key (user-scoped on Windows via Cng DPAPI when available).
/// NIST SP 800-53 SC-28 (information at rest), OWASP A02/A04 (crypto, secrets handling).
/// Vault layout: [magic 4B][version 1B][salt 16B][iv 16B][ciphertext][hmac 32B]
/// </summary>
public sealed class SecretVault
{
    private const uint Magic = 0x50535631; // "PSV1"
    private readonly byte[] _key;
    private readonly string _path;
    private Dictionary<string, string> _entries = new(StringComparer.OrdinalIgnoreCase);

    public SecretVault(string path)
    {
        _path = path;
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        _key = DeriveKey(path);
        Load();
    }

    private static byte[] DeriveKey(string vaultPath)
    {
        // Master key: DPAPI-protected blob beside the vault (machine+user scope), generated on first run.
        var masterPath = vaultPath + ".master";
        byte[] master;
        if (File.Exists(masterPath))
        {
            master = DpapiUnprotect(File.ReadAllBytes(masterPath));
        }
        else
        {
            master = RandomNumberGenerator.GetBytes(32);
            File.WriteAllBytes(masterPath, DpapiProtect(master));
            SetUserOnlyAcl(masterPath);
        }
        var salt = Encoding.UTF8.GetBytes("ProxySuite:vault:v1:" + Environment.MachineName);
        using var kdf = new Rfc2898DeriveBytes(master, salt, 100_000, HashAlgorithmName.SHA256);
        return kdf.GetBytes(32);
    }

    private static byte[] DpapiProtect(byte[] plain)
    {
        if (OperatingSystem.IsWindows())
        {
#pragma warning disable CA1416
            return System.Security.Cryptography.ProtectedData.Protect(plain, null,
                System.Security.Cryptography.DataProtectionScope.CurrentUser);
#pragma warning restore CA1416
        }
        // Non-Windows dev fallback (documented; not used in production)
        return plain;
    }

    private static byte[] DpapiUnprotect(byte[] blob)
    {
        if (OperatingSystem.IsWindows())
        {
#pragma warning disable CA1416
            return System.Security.Cryptography.ProtectedData.Unprotect(blob, null,
                System.Security.Cryptography.DataProtectionScope.CurrentUser);
#pragma warning restore CA1416
        }
        return blob;
    }

    private static void SetUserOnlyAcl(string path)
    {
        try
        {
            if (!OperatingSystem.IsWindows()) return;
            var fi = new FileInfo(path);
            var sec = fi.GetAccessControl();
            // Grant current user full control BEFORE disabling inheritance so the owner keeps access
            var currentUser = System.Security.Principal.WindowsIdentity.GetCurrent().User;
            if (currentUser is not null)
            {
                sec.AddAccessRule(new FileSystemAccessRule(currentUser,
                    FileSystemRights.FullControl, AccessControlType.Allow));
            }
            sec.SetAccessRuleProtection(true, false);
            fi.SetAccessControl(sec);
        }
        catch { /* best-effort */ }
    }

    private void Load()
    {
        if (!File.Exists(_path)) return;
        var data = File.ReadAllBytes(_path);
        if (data.Length < 4 + 1 + 16 + 16 + 32) throw new InvalidOperationException("Vault file truncated");
        var off = 0;
        if (BitConverter.ToUInt32(data, off) != Magic) throw new InvalidOperationException("Vault magic mismatch");
        off += 4;
        var version = data[off++];
        if (version != 1) throw new InvalidOperationException("Vault version unsupported");
        var salt = data[off..(off + 16)]; off += 16;
        var iv = data[off..(off + 16)]; off += 16;
        var hmac = data[^32..];
        var cipher = data[off..^32];

        using var hmacSha = new HMACSHA256(_key.Concat(salt).ToArray());
        var expected = hmacSha.ComputeHash(data[..^32]);
        if (!CryptographicOperations.FixedTimeEquals(expected, hmac))
            throw new InvalidOperationException("Vault integrity check failed (HMAC)");

        using var aes = Aes.Create();
        aes.Key = _key; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
        using var dec = aes.CreateDecryptor();
        var plain = dec.TransformFinalBlock(cipher, 0, cipher.Length);
        _entries = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(plain)
                   ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    public void Save()
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        using var aes = Aes.Create();
        aes.Key = _key; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
        aes.GenerateIV();
        using var enc = aes.CreateEncryptor();
        var plain = System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(_entries);
        var cipher = enc.TransformFinalBlock(plain, 0, plain.Length);

        using var ms = new MemoryStream();
        ms.Write(BitConverter.GetBytes(Magic));
        ms.WriteByte(1);
        ms.Write(salt);
        ms.Write(aes.IV);
        ms.Write(cipher);
        using var hmacSha = new HMACSHA256(_key.Concat(salt).ToArray());
        var hmac = hmacSha.ComputeHash(ms.ToArray());
        ms.Write(hmac);

        var tmp = _path + ".tmp";
        File.WriteAllBytes(tmp, ms.ToArray());
        if (File.Exists(_path)) File.Replace(tmp, _path, null); else File.Move(tmp, _path);
        SetUserOnlyAcl(_path);
    }

    public void Set(string name, string secret)
    {
        _entries[name] = secret;
        Save();
    }

    public bool TryGet(string name, out string secret)
    {
        return _entries.TryGetValue(name, out secret!);
    }

    public IReadOnlyCollection<string> Names => _entries.Keys.ToList();

    public bool Remove(string name) => _entries.Remove(name);
}
