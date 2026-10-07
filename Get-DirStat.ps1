<#
.SYNOPSIS
    Disk usage report (WinDirStat-style) for NinjaOne or any RMM.

.DESCRIPTION
    Scans a path (default: the system drive), totals every file under it, and reports:
      - Where the space is: User data vs OS/Programs vs Other vs Unaccounted.
      - Category totals (Profiles, Windows, Program Files, ProgramData, ...).
      - Per-profile totals with "hotspot" folders.
      - Largest files.
    The summary goes to stdout (captured by NinjaOne). A self-contained HTML report with a
    drill-down folder tree is written to -OutputDir.

    Every file is counted, so totals are exact at any depth. -MaxDepth only limits how much
    of the tree is kept for the HTML report; it does not make the scan faster.

    Read-only: the only files it changes are its own old reports in -OutputDir (-KeepReports).

.PARAMETER Path
    Folder or drive root to scan. Default: system drive root.

.PARAMETER MaxDepth
    Folder levels kept in the HTML tree below -Path (2-20). Default 5.

.PARAMETER TopFiles
    Number of largest files to list. Default 20.

.PARAMETER MinSizeMB
    Folders smaller than this are folded into a "[smaller folders]" row in the HTML tree.
    Folders at the first two levels are always kept. Default 50.

.PARAMETER OutputDir
    Folder for the HTML report. Default: $env:ProgramData\DirStat.

.PARAMETER KeepReports
    Keep this many reports for this computer in -OutputDir; older ones are deleted.
    0 keeps all. Default 5.

.EXAMPLE
    .\Get-DirStat.ps1
.EXAMPLE
    .\Get-DirStat.ps1 -Path 'D:\' -MaxDepth 6 -MinSizeMB 100
#>
[CmdletBinding()]
param(
    [string]$Path = "$env:SystemDrive\",
    [ValidateRange(2, 20)][int]$MaxDepth = 5,
    [ValidateRange(0, 500)][int]$TopFiles = 20,
    [ValidateRange(0, 1048576)][int]$MinSizeMB = 50,
    [string]$OutputDir = (Join-Path $env:ProgramData 'DirStat'),
    [ValidateRange(0, 1000)][int]$KeepReports = 5
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------------------------
# C# scanner. Compiled at runtime by the .NET 4 csc.exe that ships with Windows, so the code
# must stay at C# 5 level (no $"" strings, no ?. operator).
# Uses FindFirstFileEx directly: faster than DirectoryInfo, handles long paths through the
# \\?\ prefix, and exposes the reparse tag so junctions can be told apart from OneDrive folders.
# ---------------------------------------------------------------------------------------------
$scannerSource = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace DirStat
{
    public class DirNode
    {
        public string Name;
        public string FullPath;
        public int Depth;
        public long Size;             // Bytes on local disk, recursive (cloud-only files excluded).
        public long FileBytes;        // Bytes of files directly in this folder.
        public long DirectFileCount;
        public long FileCount;        // Recursive.
        public long FolderCount;      // Recursive.
        public long PrunedBytes;      // Child folders not kept in the tree (too small or too deep).
        public long PrunedCount;
        public bool Denied;
        public List<DirNode> Children = new List<DirNode>();
    }

    public class FileEntry
    {
        public string Path;
        public string Name;
        public long Size;
        public DateTime LastWriteUtc;
    }

    public class ScanResult
    {
        public DirNode Root;
        public List<FileEntry> TopFiles = new List<FileEntry>();
        public List<FileEntry> RootFiles = new List<FileEntry>();   // Files directly in the scan root.
        public long DeniedCount;
        public List<string> DeniedSamples = new List<string>();
        public long ErrorCount;
        public List<string> ErrorSamples = new List<string>();
        public long ReparseSkipped;
        public long CloudFiles;
        public long CloudBytes;
        public double Seconds;
    }

    public class Scanner
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WIN32_FIND_DATA
        {
            public uint dwFileAttributes;
            public uint ftCreationLow;
            public uint ftCreationHigh;
            public uint ftLastAccessLow;
            public uint ftLastAccessHigh;
            public uint ftLastWriteLow;
            public uint ftLastWriteHigh;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint dwReserved0;      // Reparse tag when FILE_ATTRIBUTE_REPARSE_POINT is set.
            public uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
            public string cAlternateFileName;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr FindFirstFileExW(string lpFileName, int fInfoLevelId,
            out WIN32_FIND_DATA lpFindFileData, int fSearchOp, IntPtr lpSearchFilter,
            int dwAdditionalFlags);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool FindNextFileW(IntPtr hFindFile, out WIN32_FIND_DATA lpFindFileData);

        [DllImport("kernel32.dll")]
        private static extern bool FindClose(IntPtr hFindFile);

        private static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);
        private const int FIND_EX_INFO_BASIC = 1;
        private const int FIND_FIRST_EX_LARGE_FETCH = 2;
        private const uint ATTR_DIRECTORY = 0x10;
        private const uint ATTR_REPARSE = 0x400;
        // OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS: OneDrive/Files On-Demand placeholders
        // report a size but have no data on the local disk.
        private const uint CLOUD_MASK = 0x1000 | 0x40000 | 0x400000;
        // Junctions and symlinks carry the name-surrogate bit; cloud folders do not.
        private const uint TAG_NAME_SURROGATE = 0x20000000;
        private const int MAX_SAMPLES = 25;

        private readonly int maxDepth;
        private readonly long minNodeBytes;
        private readonly int topN;
        private long topMin;
        private readonly List<FileEntry> top = new List<FileEntry>();
        private readonly ScanResult result = new ScanResult();

        private Scanner(int maxDepth, long minNodeBytes, int topN)
        {
            this.maxDepth = maxDepth;
            this.minNodeBytes = minNodeBytes;
            this.topN = topN;
        }

        public static ScanResult Run(string rootPath, int maxDepth, long minNodeBytes, int topFiles)
        {
            Scanner s = new Scanner(maxDepth, minNodeBytes, topFiles);
            Exception failure = null;
            Stopwatch sw = Stopwatch.StartNew();

            // Recursion depth follows folder depth. A large stack keeps very deep trees
            // (node_modules, long paths) from overflowing, which would kill the process.
            Thread t = new Thread(delegate()
            {
                try { s.result.Root = s.Walk(rootPath, rootPath, 0); }
                catch (Exception ex) { failure = ex; }
            }, 64 * 1024 * 1024);
            t.Start();
            t.Join();
            if (failure != null) { throw new Exception("Scan failed: " + failure.Message, failure); }

            s.TrimTop();
            s.result.TopFiles = s.top;
            s.result.Seconds = sw.Elapsed.TotalSeconds;
            return s.result;
        }

        private static string Join(string parent, string name)
        {
            return parent.EndsWith("\\") ? parent + name : parent + "\\" + name;
        }

        private static string ToExtended(string p)
        {
            if (p.StartsWith(@"\\?\")) { return p; }
            if (p.StartsWith(@"\\")) { return @"\\?\UNC\" + p.Substring(2); }
            return @"\\?\" + p;
        }

        private static void AddSample(List<string> list, string item)
        {
            if (list.Count < MAX_SAMPLES) { list.Add(item); }
        }

        private void TrimTop()
        {
            top.Sort(delegate(FileEntry a, FileEntry b) { return b.Size.CompareTo(a.Size); });
            if (top.Count > topN) { top.RemoveRange(topN, top.Count - topN); }
            if (topN > 0 && top.Count == topN) { topMin = top[topN - 1].Size; }
        }

        private DirNode Walk(string path, string name, int depth)
        {
            DirNode node = new DirNode();
            node.Name = name;
            node.FullPath = path;
            node.Depth = depth;

            WIN32_FIND_DATA fd;
            IntPtr h = FindFirstFileExW(ToExtended(Join(path, "*")), FIND_EX_INFO_BASIC, out fd, 0,
                IntPtr.Zero, FIND_FIRST_EX_LARGE_FETCH);
            if (h == INVALID_HANDLE)
            {
                int err = Marshal.GetLastWin32Error();
                if (err == 5)
                {
                    node.Denied = true;
                    result.DeniedCount++;
                    AddSample(result.DeniedSamples, path);
                }
                else if (err != 2 && err != 3 && err != 18)
                {
                    result.ErrorCount++;
                    AddSample(result.ErrorSamples, path + " (Win32 error " + err + ")");
                }
                return node;
            }

            try
            {
                do
                {
                    string fn = fd.cFileName;
                    if (fn == "." || fn == "..") { continue; }
                    uint a = fd.dwFileAttributes;

                    if ((a & ATTR_DIRECTORY) != 0)
                    {
                        if ((a & ATTR_REPARSE) != 0 && (fd.dwReserved0 & TAG_NAME_SURROGATE) != 0)
                        {
                            result.ReparseSkipped++;
                            continue;
                        }
                        DirNode child = Walk(Join(path, fn), fn, depth + 1);
                        node.Size += child.Size;
                        node.FileCount += child.FileCount;
                        node.FolderCount += child.FolderCount + 1;
                        // Always keep the first two levels so drive-root categories and
                        // per-profile totals exist even when they are small.
                        if (depth < maxDepth && (depth < 2 || child.Size >= minNodeBytes))
                        {
                            node.Children.Add(child);
                        }
                        else
                        {
                            node.PrunedBytes += child.Size;
                            node.PrunedCount++;
                        }
                    }
                    else
                    {
                        long size = ((long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                        if ((a & CLOUD_MASK) != 0)
                        {
                            result.CloudFiles++;
                            result.CloudBytes += size;
                            continue;
                        }
                        node.Size += size;
                        node.FileBytes += size;
                        node.FileCount++;
                        node.DirectFileCount++;
                        if (depth == 0)
                        {
                            FileEntry rf = new FileEntry();
                            rf.Path = Join(path, fn);
                            rf.Name = fn;
                            rf.Size = size;
                            result.RootFiles.Add(rf);
                        }

                        if (topN > 0 && size > topMin)
                        {
                            FileEntry fe = new FileEntry();
                            fe.Path = Join(path, fn);
                            fe.Size = size;
                            fe.LastWriteUtc = DateTime.FromFileTimeUtc(
                                ((long)fd.ftLastWriteHigh << 32) | fd.ftLastWriteLow);
                            top.Add(fe);
                            if (top.Count >= topN * 4) { TrimTop(); }
                        }
                    }
                } while (FindNextFileW(h, out fd));
            }
            finally
            {
                FindClose(h);
            }

            node.Children.Sort(delegate(DirNode x, DirNode y) { return y.Size.CompareTo(x.Size); });
            return node;
        }

        // Compact JSON for the HTML tree. ConvertTo-Json is too slow and depth-limited for this.
        public static string ToJson(DirNode root)
        {
            StringBuilder sb = new StringBuilder(1 << 20);
            WriteNode(sb, root);
            return sb.ToString();
        }

        private static void WriteNode(StringBuilder sb, DirNode n)
        {
            sb.Append("{\"n\":");
            WriteString(sb, n.Name);
            sb.Append(",\"s\":").Append(n.Size);
            sb.Append(",\"fb\":").Append(n.FileBytes);
            sb.Append(",\"df\":").Append(n.DirectFileCount);
            sb.Append(",\"f\":").Append(n.FileCount);
            sb.Append(",\"d\":").Append(n.FolderCount);
            if (n.PrunedCount > 0)
            {
                sb.Append(",\"pb\":").Append(n.PrunedBytes);
                sb.Append(",\"pc\":").Append(n.PrunedCount);
            }
            if (n.Denied) { sb.Append(",\"x\":1"); }
            if (n.Children.Count > 0)
            {
                sb.Append(",\"c\":[");
                for (int i = 0; i < n.Children.Count; i++)
                {
                    if (i > 0) { sb.Append(','); }
                    WriteNode(sb, n.Children[i]);
                }
                sb.Append(']');
            }
            sb.Append('}');
        }

        // Escapes < > & too, so a file name can never close the <script> block it is embedded in.
        private static void WriteString(StringBuilder sb, string s)
        {
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    default:
                        if (c < 0x20 || c == '<' || c == '>' || c == '&' || c == '\u2028' || c == '\u2029')
                        {
                            sb.Append("\\u").Append(((int)c).ToString("x4"));
                        }
                        else
                        {
                            sb.Append(c);
                        }
                        break;
                }
            }
            sb.Append('"');
        }
    }
}
'@

# ---------------------------------------------------------------------------------------------
# HTML template. Placeholders are replaced with String.Replace (not regex), so $ and \ in the
# data are safe.
# ---------------------------------------------------------------------------------------------
$htmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#fff;--fg:#1d2329;--mut:#66707a;--line:#e3e7eb;--card:#f5f7f9;--hover:#eef2f6;--bar:#3b82f6;--user:#e8590c;--sys:#1c7ed6;--oth:#7950f2;--un:#adb5bd;--warn:#c92a2a}
@media (prefers-color-scheme:dark){:root{--bg:#14181c;--fg:#e6e9ec;--mut:#9aa4ae;--line:#2a3138;--card:#1b2026;--hover:#222a31;--bar:#4c8df6;--un:#5c636a;--warn:#ff8787}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 "Segoe UI",system-ui,sans-serif}
main{max-width:1200px;margin:0 auto;padding:16px}
h1{font-size:22px;margin:0 0 4px}
h2{font-size:16px;margin:28px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.mut{color:var(--mut)}
.stack{display:flex;height:28px;border-radius:6px;overflow:hidden;background:var(--line);margin:8px 0}
.stack div{height:100%}
.legend{display:flex;flex-wrap:wrap;gap:8px 20px;margin-top:6px}
.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:6px;vertical-align:middle}
.wrap{overflow-x:auto}
table{border-collapse:collapse;width:100%}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-weight:600;color:var(--mut);font-size:12px;text-transform:uppercase;letter-spacing:.03em}
td.r,th.r{text-align:right;white-space:nowrap}
td.path{word-break:break-all}
.hot{font-size:12px;color:var(--mut)}
.pbar{display:inline-block;width:80px;height:8px;background:var(--line);border-radius:4px;overflow:hidden;vertical-align:middle;margin-left:6px}
.pbar i{display:block;height:100%;background:var(--bar)}
.tree{border:1px solid var(--line);border-radius:6px;overflow:hidden}
.row{display:grid;grid-template-columns:16px minmax(0,1fr) 120px 84px 60px 120px;gap:8px;align-items:center;padding:3px 8px;border-bottom:1px solid var(--line)}
.row.click{cursor:pointer}
.row.click:hover{background:var(--hover)}
.row .nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.row .bar{height:8px;background:var(--line);border-radius:4px;overflow:hidden}
.row .bar i{display:block;height:100%;background:var(--bar)}
.row .sz,.row .pc,.row .fc{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums}
.row .pc,.row .fc{color:var(--mut);font-size:12px}
.row.pseudo .nm{color:var(--mut);font-style:italic}
.tag{font-size:11px;color:var(--warn);margin-left:8px;font-style:normal}
ul{padding-left:20px}
@media (max-width:640px){.row{grid-template-columns:16px minmax(0,1fr) 76px 52px}.row .bar,.row .fc{display:none}.pbar{display:none}}
</style>
</head>
<body>
<main>
<h1 id="title"></h1>
<div id="sub" class="mut"></div>
<div id="drive" class="mut"></div>

<h2>Where the space is</h2>
<div id="stack" class="stack"></div>
<div id="legend" class="legend"></div>

<h2>Categories</h2>
<div class="wrap"><table id="cats"></table></div>

<div id="profSec">
<h2>User profiles</h2>
<div class="wrap"><table id="profiles"></table></div>
</div>

<h2>Folder tree</h2>
<p class="mut">Click a folder to expand. Sorted largest first. Kept to depth <span id="depth"></span>; folders under <span id="minmb"></span> MB are folded into one row.</p>
<div id="tree" class="tree"></div>

<h2>Largest files</h2>
<div class="wrap"><table id="files"></table></div>

<h2>Notes</h2>
<ul id="notes"></ul>
</main>
<script>
var META = __META__;
var TREE = __TREE__;
(function () {
  'use strict';
  var M = META;
  var GROUP_COLOR = { 'User data': 'var(--user)', 'OS/Programs': 'var(--sys)', 'Other': 'var(--oth)', 'Unaccounted': 'var(--un)' };

  function byId(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) { e.className = cls; }
    if (text !== undefined && text !== null) { e.textContent = text; }
    return e;
  }
  function fmt(b) {
    if (b < 1024) { return b + ' B'; }
    var u = ['KB', 'MB', 'GB', 'TB', 'PB'], i = -1;
    do { b /= 1024; i++; } while (b >= 1024 && i < u.length - 1);
    return b.toFixed(b < 10 ? 2 : 1) + ' ' + u[i];
  }
  function pct(a, b) { return b > 0 ? a * 100 / b : 0; }
  function num(n) { return Number(n).toLocaleString(); }
  function td(text, cls) { return el('td', cls, text); }
  function head(table, cols) {
    var tr = el('tr');
    cols.forEach(function (c) { tr.appendChild(el('th', c.r ? 'r' : '', c.t)); });
    var th = el('thead'); th.appendChild(tr); table.appendChild(th);
    var tb = el('tbody'); table.appendChild(tb); return tb;
  }
  function pctCell(a, b) {
    var c = td(pct(a, b).toFixed(1) + '%', 'r');
    var bar = el('span', 'pbar'); var i = el('i');
    i.style.width = Math.min(100, pct(a, b)).toFixed(1) + '%';
    bar.appendChild(i); c.appendChild(bar); return c;
  }
  function hotCell(list) {
    var c = td(null, 'hot');
    (list || []).forEach(function (h) { c.appendChild(el('div', null, h.path + '  ' + fmt(h.bytes))); });
    return c;
  }

  // Header
  byId('title').textContent = 'Disk usage: ' + M.host;
  document.title = 'DirStat ' + M.host;
  byId('sub').textContent = M.path + ' \u00b7 ' + M.generated + ' \u00b7 scanned ' + fmt(M.scan.bytes) +
    ' in ' + num(M.scan.files) + ' files, ' + num(M.scan.folders) + ' folders, ' + M.scan.seconds + ' s';
  if (M.drive) {
    byId('drive').textContent = 'Drive ' + M.drive.name + ': total ' + fmt(M.drive.total) + ' \u00b7 used ' +
      fmt(M.drive.used) + ' (' + pct(M.drive.used, M.drive.total).toFixed(0) + '%) \u00b7 free ' + fmt(M.drive.free);
  }
  byId('depth').textContent = M.maxDepth;
  byId('minmb').textContent = M.minSizeMB;

  // Group bar
  M.groups.forEach(function (g) {
    if (g.bytes <= 0) { return; }
    var d = el('div'); d.style.width = pct(g.bytes, M.basis).toFixed(2) + '%';
    d.style.background = GROUP_COLOR[g.name]; d.title = g.name + ': ' + fmt(g.bytes);
    byId('stack').appendChild(d);
    var l = el('span'); var dot = el('span', 'dot'); dot.style.background = GROUP_COLOR[g.name];
    l.appendChild(dot);
    l.appendChild(document.createTextNode(g.name + ' ' + fmt(g.bytes) + ' (' + pct(g.bytes, M.basis).toFixed(0) + '%)'));
    byId('legend').appendChild(l);
  });

  // Categories
  var tb = head(byId('cats'), [{ t: 'Category' }, { t: 'Group' }, { t: 'Size', r: 1 }, { t: '% of used', r: 1 }, { t: 'Largest folders' }]);
  M.categories.forEach(function (c) {
    var tr = el('tr'); var n = td(null); var dot = el('span', 'dot'); dot.style.background = GROUP_COLOR[c.group];
    n.appendChild(dot); n.appendChild(document.createTextNode(c.name));
    tr.appendChild(n); tr.appendChild(td(c.group)); tr.appendChild(td(fmt(c.bytes), 'r'));
    tr.appendChild(pctCell(c.bytes, M.basis)); tr.appendChild(hotCell(c.hotspots)); tb.appendChild(tr);
  });

  // Profiles
  if (M.profiles.length === 0) { byId('profSec').hidden = true; }
  else {
    tb = head(byId('profiles'), [{ t: 'Profile' }, { t: 'Size', r: 1 }, { t: '% of used', r: 1 }, { t: 'Files', r: 1 }, { t: 'Largest folders' }]);
    M.profiles.forEach(function (p) {
      var tr = el('tr'); var n = td(p.name);
      if (p.denied) { n.appendChild(el('span', 'tag', 'access denied')); }
      tr.appendChild(n); tr.appendChild(td(fmt(p.bytes), 'r')); tr.appendChild(pctCell(p.bytes, M.basis));
      tr.appendChild(td(num(p.files), 'r')); tr.appendChild(hotCell(p.hotspots)); tb.appendChild(tr);
    });
  }

  // Largest files
  tb = head(byId('files'), [{ t: 'Size', r: 1 }, { t: 'Modified' }, { t: 'Path' }]);
  M.files.forEach(function (f) {
    var tr = el('tr'); tr.appendChild(td(fmt(f.bytes), 'r')); tr.appendChild(td(f.modified));
    tr.appendChild(td(f.path, 'path')); tb.appendChild(tr);
  });

  // Notes
  M.notes.forEach(function (n) { byId('notes').appendChild(el('li', null, n)); });

  // Tree: child rows are built on first expand, so large trees open fast.
  function join(p, n) { return p.charAt(p.length - 1) === '\\' ? p + n : p + '\\' + n; }
  function makeRow(label, size, files, depth, parentSize, title, pseudo) {
    var r = el('div', 'row' + (pseudo ? ' pseudo' : ''));
    r.style.paddingLeft = (depth * 16 + 8) + 'px';
    var tw = el('span', 'tw', ''); var nm = el('span', 'nm', label); if (title) { nm.title = title; }
    var bar = el('span', 'bar'); var fill = el('i');
    fill.style.width = (parentSize ? pct(size, parentSize) : 100).toFixed(1) + '%'; bar.appendChild(fill);
    r.appendChild(tw); r.appendChild(nm); r.appendChild(bar);
    r.appendChild(el('span', 'sz', fmt(size)));
    r.appendChild(el('span', 'pc', parentSize ? pct(size, parentSize).toFixed(1) + '%' : ''));
    r.appendChild(el('span', 'fc', files === null ? '' : num(files) + ' files'));
    return { row: r, tw: tw, nm: nm };
  }
  function buildNode(node, depth, parentSize, path) {
    var wrap = el('div');
    var parts = makeRow(node.n, node.s, node.f, depth, parentSize, path, false);
    if (node.x) { parts.nm.appendChild(el('span', 'tag', 'access denied')); }
    wrap.appendChild(parts.row);
    var hasKids = (node.c && node.c.length) || node.fb > 0 || node.pc > 0;
    if (!hasKids) { return wrap; }
    var kids = el('div'); kids.hidden = true; wrap.appendChild(kids);
    var built = false;
    parts.row.className += ' click'; parts.tw.textContent = '\u25b8';
    parts.row.onclick = function () {
      if (!built) { fillKids(kids, node, depth + 1, path); built = true; }
      kids.hidden = !kids.hidden; parts.tw.textContent = kids.hidden ? '\u25b8' : '\u25be';
    };
    wrap.toggle = parts.row.onclick;
    return wrap;
  }
  function fillKids(container, node, depth, path) {
    var items = [];
    (node.c || []).forEach(function (c) { items.push({ k: 'd', n: c, s: c.s }); });
    if (node.fb > 0) { items.push({ k: 'f', s: node.fb }); }
    if (node.pc > 0) { items.push({ k: 'p', s: node.pb }); }
    items.sort(function (a, b) { return b.s - a.s; });
    items.forEach(function (it) {
      if (it.k === 'd') { container.appendChild(buildNode(it.n, depth, node.s, join(path, it.n.n))); return; }
      var label, files = null;
      if (it.k === 'f') { label = '[' + num(node.df) + ' files in this folder]'; files = node.df; }
      else if (depth > M.maxDepth) { label = '[' + num(node.pc) + ' subfolders below depth limit]'; }
      else { label = '[' + num(node.pc) + ' folders under ' + M.minSizeMB + ' MB]'; }
      container.appendChild(makeRow(label, it.s, files, depth, node.s, null, true).row);
    });
  }
  var root = buildNode(TREE, 0, 0, TREE.n);
  byId('tree').appendChild(root);
  if (root.toggle) { root.toggle(); }
})();
</script>
</body>
</html>
'@

function Format-Size {
    param([double]$Bytes)
    $abs = [math]::Abs($Bytes)
    if ($abs -ge 1TB) { return '{0:N2} TB' -f ($Bytes / 1TB) }
    if ($abs -ge 1GB) { return '{0:N1} GB' -f ($Bytes / 1GB) }
    if ($abs -ge 1MB) { return '{0:N1} MB' -f ($Bytes / 1MB) }
    if ($abs -ge 1KB) { return '{0:N0} KB' -f ($Bytes / 1KB) }
    return '{0:N0} B' -f $Bytes
}

function Get-Percent {
    param([double]$Part, [double]$Whole)
    if ($Whole -le 0) { return 0 }
    return [math]::Round($Part * 100 / $Whole, 1)
}

function Test-PathUnder {
    param([string]$FullPath, [string]$Parent)
    $p = $Parent.TrimEnd('\')
    $f = $FullPath.TrimEnd('\')
    return ($f -eq $p) -or $f.StartsWith($p + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Find-Node {
    param($Root, [string]$FullPath)
    $node = $Root
    while ($null -ne $node) {
        if ($node.FullPath.TrimEnd('\') -eq $FullPath.TrimEnd('\')) { return $node }
        $next = $null
        foreach ($c in $node.Children) {
            if (Test-PathUnder -FullPath $FullPath -Parent $c.FullPath) { $next = $c; break }
        }
        $node = $next
    }
    return $null
}

# Largest-first drill: take the biggest folder in the pool. If one child holds >= 25% of it,
# replace it with its children and repeat; otherwise it is a hotspot. Finds e.g.
# AppData\Local\Docker\wsl\disk and AppData\Local\Microsoft\Outlook as separate entries
# instead of stopping at AppData\Local.
function Get-Hotspots {
    param([object[]]$Nodes, [int]$Count, [string]$RelativeTo)
    $pool = New-Object System.Collections.ArrayList
    foreach ($n in $Nodes) {
        if ($n.Children.Count -gt 0) { $pool.AddRange($n.Children) } else { [void]$pool.Add($n) }
    }
    $found = New-Object System.Collections.ArrayList
    while ($found.Count -lt $Count -and $pool.Count -gt 0) {
        $best = $pool[0]
        foreach ($c in $pool) { if ($c.Size -gt $best.Size) { $best = $c } }
        $pool.Remove($best)
        if ($best.Size -le 0) { break }
        if ($best.Children.Count -gt 0 -and $best.Children[0].Size -ge ($best.Size * 0.25)) {
            $pool.AddRange($best.Children)
        } else {
            [void]$found.Add($best)
        }
    }
    $result = foreach ($h in $found) {
        $display = $h.FullPath
        if ($RelativeTo -and (Test-PathUnder -FullPath $h.FullPath -Parent $RelativeTo)) {
            $display = $h.FullPath.Substring($RelativeTo.TrimEnd('\').Length).TrimStart('\')
            if (-not $display) { $display = '(files in root)' }
        }
        [pscustomobject]@{ path = $display; bytes = [long]$h.Size }
    }
    return @($result)
}

try {
    # --- Resolve path -----------------------------------------------------------------------
    # "C:" alone means "current dir on C:" to .NET, so make it the drive root explicitly.
    if ($Path -match '^[A-Za-z]:$') { $Path += '\' }
    $rootPath = [System.IO.Path]::GetFullPath($Path)
    if ($rootPath -notmatch '^[A-Za-z]:\\$') { $rootPath = $rootPath.TrimEnd('\') }
    if (-not (Test-Path -LiteralPath $rootPath -PathType Container)) {
        throw "Path not found or not a folder: $rootPath"
    }
    $isDriveRoot = $rootPath -match '^[A-Za-z]:\\$'

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)

    # --- Compile and scan -------------------------------------------------------------------
    if (-not ('DirStat.Scanner' -as [type])) {
        try {
            Add-Type -TypeDefinition $scannerSource -Language CSharp
        } catch {
            throw "Could not compile the C# scanner (Add-Type / csc.exe blocked?): $($_.Exception.Message)"
        }
    }
    $scan = [DirStat.Scanner]::Run($rootPath, $MaxDepth, [long]$MinSizeMB * 1MB, $TopFiles)
    $root = $scan.Root

    # --- Drive info -------------------------------------------------------------------------
    $drive = $null
    $vssUsed = $null
    if ($isDriveRoot) {
        $di = New-Object System.IO.DriveInfo($rootPath.Substring(0, 1))
        $drive = [pscustomobject]@{
            name  = $rootPath.Substring(0, 2)
            total = [long]$di.TotalSize
            used  = [long]($di.TotalSize - $di.TotalFreeSpace)
            free  = [long]$di.TotalFreeSpace
        }
        try {
            $vol = Get-CimInstance -ClassName Win32_Volume -Filter "DriveLetter='$($drive.name)'"
            if ($vol) {
                $ss = @(Get-CimInstance -ClassName Win32_ShadowStorage |
                        Where-Object { $_.Volume.DeviceID -eq $vol.DeviceID })
                if ($ss.Count -gt 0) { $vssUsed = [long]($ss | Measure-Object -Property UsedSpace -Sum).Sum }
            }
        } catch {
            $vssUsed = $null
        }
    }

    # --- Categories -------------------------------------------------------------------------
    $profilesDir = $null
    try {
        $profilesDir = [Environment]::ExpandEnvironmentVariables((Get-ItemProperty -LiteralPath `
                    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList').ProfilesDirectory)
    } catch {
        $profilesDir = Join-Path $env:SystemDrive 'Users'
    }
    $sysDrive = $env:SystemDrive
    $rules = @(
        [pscustomobject]@{ Name = 'User Profiles'; Group = 'User data'; Paths = @($profilesDir) }
        [pscustomobject]@{ Name = 'Recycle Bin'; Group = 'User data'; Paths = @("$($rootPath.Substring(0, 2))\`$Recycle.Bin") }
        [pscustomobject]@{ Name = 'Windows'; Group = 'OS/Programs'; Paths = @($env:SystemRoot) }
        [pscustomobject]@{ Name = 'Program Files'; Group = 'OS/Programs'; Paths = @($env:ProgramFiles, ${env:ProgramFiles(x86)}) }
        [pscustomobject]@{ Name = 'ProgramData'; Group = 'OS/Programs'; Paths = @($env:ProgramData) }
        [pscustomobject]@{ Name = 'Windows.old / upgrade files'; Group = 'OS/Programs'; Paths = @(
                "$sysDrive\Windows.old", "$sysDrive\`$WINDOWS.~BT", "$sysDrive\`$WINDOWS.~WS",
                "$sysDrive\`$WinREAgent", "$sysDrive\`$GetCurrent", "$sysDrive\ESD") }
        [pscustomobject]@{ Name = 'System Volume Information'; Group = 'OS/Programs'; Paths = @("$($rootPath.Substring(0, 2))\System Volume Information") }
    )
    $systemFilesRule = [pscustomobject]@{ Name = 'System files (page/hiber/swap)'; Group = 'OS/Programs'; Paths = @() }
    $otherRule = [pscustomobject]@{ Name = 'Other'; Group = 'Other'; Paths = @() }

    function Get-PathRule {
        param([string]$FullPath)
        foreach ($rule in $rules) {
            foreach ($p in $rule.Paths) {
                if ($p -and (Test-PathUnder -FullPath $FullPath -Parent $p)) { return $rule }
            }
        }
        return $otherRule
    }

    $catData = [ordered]@{}
    function Add-ToCategory {
        param($Rule, [long]$Bytes, $Node)
        if (-not $catData.Contains($Rule.Name)) {
            $catData[$Rule.Name] = [pscustomobject]@{
                Rule = $Rule; Bytes = [long]0; Nodes = (New-Object System.Collections.ArrayList)
            }
        }
        $catData[$Rule.Name].Bytes += $Bytes
        if ($null -ne $Node) { [void]$catData[$Rule.Name].Nodes.Add($Node) }
    }

    foreach ($child in $root.Children) {
        Add-ToCategory -Rule (Get-PathRule -FullPath $child.FullPath) -Bytes $child.Size -Node $child
    }
    $rootFileBytes = [long]$root.FileBytes
    if ($isDriveRoot) {
        # Sizes come from the scanner: Get-Item on pagefile.sys fails when not elevated.
        $sysFileBytes = [long]0
        foreach ($f in $scan.RootFiles) {
            if (@('pagefile.sys', 'hiberfil.sys', 'swapfile.sys') -contains $f.Name) { $sysFileBytes += $f.Size }
        }
        if ($sysFileBytes -gt 0) { Add-ToCategory -Rule $systemFilesRule -Bytes $sysFileBytes -Node $null }
        if ($rootFileBytes - $sysFileBytes -gt 0) {
            Add-ToCategory -Rule $otherRule -Bytes ($rootFileBytes - $sysFileBytes) -Node $null
        }
    } elseif ($rootFileBytes -gt 0) {
        Add-ToCategory -Rule (Get-PathRule -FullPath $rootPath) -Bytes $rootFileBytes -Node $null
    }

    # Percent basis: used space on the drive. If hard links / compression make the scan larger
    # than used space, use the scan total so percentages stay at or below 100.
    $scannedBytes = [long]$root.Size
    $unaccounted = [long]0
    $basis = $scannedBytes
    if ($drive) {
        $unaccounted = $drive.used - $scannedBytes
        $basis = [math]::Max($drive.used, $scannedBytes)
    }

    $categories = @($catData.Values | Sort-Object -Property Bytes -Descending | ForEach-Object {
            $relative = $null
            if (@($_.Nodes).Count -eq 1) { $relative = $_.Nodes[0].FullPath }
            [pscustomobject]@{
                name     = $_.Rule.Name
                group    = $_.Rule.Group
                bytes    = [long]$_.Bytes
                hotspots = @(Get-Hotspots -Nodes @($_.Nodes) -Count 3 -RelativeTo $relative)
            }
        })

    $groups = foreach ($g in 'User data', 'OS/Programs', 'Other') {
        $sum = [long]0
        foreach ($c in $categories) { if ($c.group -eq $g) { $sum += $c.bytes } }
        [pscustomobject]@{ name = $g; bytes = $sum }
    }
    if ($drive) { $groups = @($groups) + [pscustomobject]@{ name = 'Unaccounted'; bytes = [math]::Max([long]0, $unaccounted) } }
    $groups = @($groups)

    # --- Profiles ---------------------------------------------------------------------------
    $profiles = @()
    $usersNode = $null
    if ($profilesDir) { $usersNode = Find-Node -Root $root -FullPath $profilesDir }
    if ($null -ne $usersNode) {
        $profiles = @(foreach ($p in $usersNode.Children) {
                [pscustomobject]@{
                    name     = $p.Name
                    bytes    = [long]$p.Size
                    files    = [long]$p.FileCount
                    denied   = [bool]$p.Denied
                    hotspots = @(Get-Hotspots -Nodes @($p) -Count 3 -RelativeTo $p.FullPath)
                }
            })
    }

    # --- Notes ------------------------------------------------------------------------------
    $notes = New-Object System.Collections.Generic.List[string]
    if (-not $isAdmin) {
        $notes.Add('Not running elevated: other profiles and system folders were likely skipped. Run as SYSTEM or admin.')
    }
    if ($scan.DeniedCount -gt 0) {
        $notes.Add(('Access denied on {0:N0} folders (not counted). First: {1}' -f
                $scan.DeniedCount, (@($scan.DeniedSamples | Select-Object -First 5) -join '; ')))
    }
    if ($scan.ErrorCount -gt 0) {
        $notes.Add(('Other read errors on {0:N0} folders. First: {1}' -f
                $scan.ErrorCount, (@($scan.ErrorSamples | Select-Object -First 5) -join '; ')))
    }
    if ($scan.CloudFiles -gt 0) {
        $notes.Add(('OneDrive/cloud-only files: {0:N0} files, {1} (not on local disk, not counted).' -f
                $scan.CloudFiles, (Format-Size $scan.CloudBytes)))
    }
    if ($scan.ReparseSkipped -gt 0) {
        $notes.Add(('Skipped {0:N0} junctions/symlinks to avoid double counting.' -f $scan.ReparseSkipped))
    }
    if ($drive) {
        if ($unaccounted -ge 0) {
            $notes.Add(('Unaccounted {0} = used space minus scanned files: NTFS metadata, denied folders, files in use.' -f
                    (Format-Size $unaccounted)))
        } else {
            $notes.Add(('Scanned files exceed used space by {0}: hard links (WinSxS) and compressed files are counted at full size.' -f
                    (Format-Size (-$unaccounted))))
        }
        if ($null -ne $vssUsed) {
            $notes.Add(('Shadow copy (restore point) storage in use: {0} (inside System Volume Information).' -f
                    (Format-Size $vssUsed)))
        }
    }
    $notes.Add('Sizes are logical file sizes. WinSxS hard links make Windows look larger than its real disk use.')

    # --- HTML report ------------------------------------------------------------------------
    $now = Get-Date
    $htmlPath = $null
    $htmlError = $null
    try {
        if (-not (Test-Path -LiteralPath $OutputDir)) {
            [void](New-Item -ItemType Directory -Path $OutputDir -Force)
        }
        $htmlPath = Join-Path $OutputDir ('DirStat_{0}_{1}.html' -f $env:COMPUTERNAME, $now.ToString('yyyyMMdd_HHmmss'))

        $meta = [pscustomobject]@{
            host       = $env:COMPUTERNAME
            generated  = $now.ToString('yyyy-MM-dd HH:mm')
            path       = $rootPath
            maxDepth   = $MaxDepth
            minSizeMB  = $MinSizeMB
            basis      = [long]$basis
            drive      = $drive
            scan       = [pscustomobject]@{
                bytes   = $scannedBytes
                files   = [long]$root.FileCount
                folders = [long]$root.FolderCount
                seconds = [math]::Round($scan.Seconds, 1)
            }
            groups     = $groups
            categories = $categories
            profiles   = $profiles
            files      = @(foreach ($f in $scan.TopFiles) {
                    [pscustomobject]@{
                        path     = $f.Path
                        bytes    = [long]$f.Size
                        modified = $f.LastWriteUtc.ToLocalTime().ToString('yyyy-MM-dd')
                    }
                })
            notes      = @($notes)
        }
        # "</" inside a string would end the <script> block early.
        $metaJson = (ConvertTo-Json -InputObject $meta -Depth 8 -Compress).Replace('</', '<\/')
        # Splice by index, not chained Replace(): a file named "__TREE__" must not be replaced.
        $tpl = $htmlTemplate.Replace('__TITLE__', "DirStat $env:COMPUTERNAME")
        $iMeta = $tpl.IndexOf('__META__')
        $iTree = $tpl.IndexOf('__TREE__')
        $html = $tpl.Substring(0, $iMeta) + $metaJson +
            $tpl.Substring($iMeta + 8, $iTree - $iMeta - 8) + [DirStat.Scanner]::ToJson($root) +
            $tpl.Substring($iTree + 8)
        [System.IO.File]::WriteAllText($htmlPath, $html, (New-Object System.Text.UTF8Encoding($false)))

        if ($KeepReports -gt 0) {
            Get-ChildItem -LiteralPath $OutputDir -Filter "DirStat_$($env:COMPUTERNAME)_*.html" -File |
                Sort-Object -Property LastWriteTime -Descending |
                Select-Object -Skip $KeepReports |
                Remove-Item -Force
        }
    } catch {
        $htmlError = $_.Exception.Message
    }

    # --- Stdout summary (NinjaOne activity output) ------------------------------------------
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(('=== DirStat {0}  {1}  {2} ===' -f $env:COMPUTERNAME, $rootPath, $now.ToString('yyyy-MM-dd HH:mm')))
    if ($drive) {
        $lines.Add(('Drive {0}  Total {1} | Used {2} ({3}%) | Free {4}' -f $drive.name, (Format-Size $drive.total),
                (Format-Size $drive.used), (Get-Percent $drive.used $drive.total), (Format-Size $drive.free)))
    }
    $lines.Add(('Scanned {0} in {1:N0} files, {2:N0} folders, {3:N1} s' -f (Format-Size $scannedBytes),
            $root.FileCount, $root.FolderCount, $scan.Seconds))
    $lines.Add('')
    $lines.Add('WHERE THE SPACE IS (% of used)')
    foreach ($g in $groups) {
        if ($g.bytes -le 0) { continue }
        $lines.Add(('  {0,-14} {1,10}  {2,5}%' -f $g.name, (Format-Size $g.bytes), (Get-Percent $g.bytes $basis)))
    }
    $lines.Add('')
    $lines.Add('CATEGORIES')
    foreach ($c in $categories) {
        $lines.Add(('  {0,-32} {1,10}  {2,5}%' -f $c.name, (Format-Size $c.bytes), (Get-Percent $c.bytes $basis)))
        foreach ($h in $c.hotspots) {
            $lines.Add(('      {0,10}  {1}' -f (Format-Size $h.bytes), $h.path))
        }
    }
    if ($profiles.Count -gt 0) {
        $lines.Add('')
        $lines.Add(('TOP PROFILES ({0} total)' -f $profiles.Count))
        foreach ($p in @($profiles | Select-Object -First 10)) {
            $flag = ''
            if ($p.denied) { $flag = '  [access denied]' }
            $lines.Add(('  {0,-32} {1,10}  {2,5}%{3}' -f $p.name, (Format-Size $p.bytes), (Get-Percent $p.bytes $basis), $flag))
            foreach ($h in $p.hotspots) {
                $lines.Add(('      {0,10}  {1}' -f (Format-Size $h.bytes), $h.path))
            }
        }
    }
    if ($scan.TopFiles.Count -gt 0) {
        $lines.Add('')
        $lines.Add(('TOP {0} FILES' -f $scan.TopFiles.Count))
        foreach ($f in $scan.TopFiles) {
            $lines.Add(('  {0,10}  {1}' -f (Format-Size $f.Size), $f.Path))
        }
    }
    $lines.Add('')
    $lines.Add('NOTES')
    foreach ($n in $notes) { $lines.Add("  - $n") }
    $lines.Add('')
    if ($htmlError) {
        $lines.Add("HTML report FAILED: $htmlError")
    } else {
        $lines.Add("HTML report: $htmlPath")
    }
    $lines | Write-Output

    if ($htmlError) { exit 1 }
    exit 0
} catch {
    Write-Output "ERROR: $($_.Exception.Message)"
    exit 1
}
