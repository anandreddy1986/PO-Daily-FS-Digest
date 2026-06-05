# Linux Kernel Filesystem Stack - FS Teams Architecture

**How FS (General) Fits Into the Kernel**

---

## 📊 VERTICAL STACK VIEW

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          USER SPACE                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │ Applications │  │  Web Servers │  │   Databases  │  │  Antivirus  │ │
│  │   (cp, ls)   │  │ (nginx, etc) │  │  (postgres)  │  │   Scanner   │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘ │
└─────────┼──────────────────┼──────────────────┼──────────────────┼──────┘
          │                  │                  │                  │
          ▼                  ▼                  ▼                  ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                    SYSTEM CALL INTERFACE (syscalls)                      │
│  open() read() write() close() stat() epoll_wait() fanotify_mark() etc. │
└─────────────────────────────────────────────────────────────────────────┘
          │
          ▼
╔═════════════════════════════════════════════════════════════════════════╗
║                   VIRTUAL FILE SYSTEM (VFS) LAYER                        ║
║  ┌────────────────────────────────────────────────────────────────┐    ║
║  │  Common FS Infrastructure (FS-VFS team handles this)            │    ║
║  │  • Inode cache • Dentry cache • Page cache • File locks        │    ║
║  │  • Generic file operations • Pathname lookup                    │    ║
║  └────────────────────────────────────────────────────────────────┘    ║
╚═════════════════════════════════════════════════════════════════════════╝
          │
          ├──────────────────┬────────────────┬────────────────┬───────────
          ▼                  ▼                ▼                ▼
┌─────────────────┐  ┌─────────────────────────────────────────────────────┐
│  PSEUDO/VIRTUAL │  │         SPECIFIC FILESYSTEM IMPLEMENTATIONS         │
│   FILESYSTEMS   │  │                                                     │
│                 │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
│ ╔═════════════╗ │  │  │   ext4   │  │   XFS    │  │  Btrfs   │         │
│ ║ FS (General)║ │  │  │ FS-local │  │ FS-local │  │ FS-local │         │
│ ╚═════════════╝ │  │  └──────────┘  └──────────┘  └──────────┘         │
│                 │  │                                                     │
│  ┌───────────┐  │  │  ┌──────────┐  ┌──────────┐  ┌──────────┐         │
│  │  procfs   │  │  │  │   NFS    │  │   CIFS   │  │   SMB    │         │
│  │ /proc/    │  │  │  │ FS-Net   │  │ FS-Net   │  │ FS-Net   │         │
│  └───────────┘  │  │  └──────────┘  └──────────┘  └──────────┘         │
│                 │  │                                                     │
│  ┌───────────┐  │  │  ┌──────────┐                                     │
│  │ sysfs     │  │  │  │  GFS2    │                                     │
│  │ /sys/     │  │  │  │ FS-GFS2  │                                     │
│  └───────────┘  │  │  └──────────┘                                     │
│                 │  │                                                     │
│  ┌───────────┐  │  └─────────────────────────────────────────────────────┘
│  │ tmpfs     │  │
│  │ (RAM)     │  │
│  └───────────┘  │
└─────────────────┘
          │                                 │
          ▼                                 ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                          BLOCK LAYER                                     │
│  • I/O scheduling • Request queuing • Device drivers                    │
└─────────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                      PHYSICAL STORAGE                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │   HDD    │  │   SSD    │  │  Network │  │   RAM    │               │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘               │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 🔄 FS (GENERAL) COMPONENTS - DETAILED VIEW

```
┌───────────────────────────────────────────────────────────────────────────┐
│                          USER SPACE APPLICATIONS                           │
└───────┬───────────────────┬────────────────────┬──────────────────────────┘
        │                   │                    │
        │ ps, top, htop    │ nginx, postgres    │ antivirus, backup
        │ read /proc/      │ epoll_wait()       │ fanotify_mark()
        ▼                   ▼                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SYSTEM CALL INTERFACE                                │
└─────────────────────────────────────────────────────────────────────────────┘
        │                   │                    │
        ▼                   ▼                    ▼
╔═══════════════════════════════════════════════════════════════════════════╗
║                        FS (GENERAL) SUBSYSTEMS                             ║
║                                                                            ║
║  ┌──────────────────────────────────────────────────────────────────┐    ║
║  │ 1. procfs (Process Filesystem) - 25% workload                    │    ║
║  │    • Virtual FS mounted at /proc                                 │    ║
║  │    • Exposes kernel/process info as files                        │    ║
║  │    • No physical storage backend                                 │    ║
║  │                                                                   │    ║
║  │    /proc/[pid]/                                                   │    ║
║  │    ├── cmdline    (process command line)                         │    ║
║  │    ├── status     (process status)                               │    ║
║  │    ├── fd/        (open file descriptors)                        │    ║
║  │    └── maps       (memory mappings)                              │    ║
║  │                                                                   │    ║
║  │    /proc/sys/     (kernel tunables)                              │    ║
║  │    /proc/cpuinfo  (CPU information)                              │    ║
║  │    /proc/meminfo  (memory statistics)                            │    ║
║  │                                                                   │    ║
║  │    CVEs: CVE-2026-46259 (RCU protection), CVE-2025-38653         │    ║
║  └──────────────────────────────────────────────────────────────────┘    ║
║                                                                            ║
║  ┌──────────────────────────────────────────────────────────────────┐    ║
║  │ 2. eventpoll (epoll) - Event Notification - 27% workload         │    ║
║  │    • Scalable I/O event notification mechanism                   │    ║
║  │    • Used by high-performance apps (web servers, DBs)            │    ║
║  │    • Monitors multiple file descriptors efficiently              │    ║
║  │                                                                   │    ║
║  │    System Calls:                                                 │    ║
║  │    ┌─────────────────────────────────────────────────────┐      │    ║
║  │    │ epoll_create() → Create epoll instance              │      │    ║
║  │    │ epoll_ctl()    → Add/remove/modify file descriptors │      │    ║
║  │    │ epoll_wait()   → Wait for events                    │      │    ║
║  │    └─────────────────────────────────────────────────────┘      │    ║
║  │                                                                   │    ║
║  │    Use Cases:                                                     │    ║
║  │    • nginx handling 10,000+ connections                          │    ║
║  │    • PostgreSQL async I/O                                        │    ║
║  │    • Redis event loop                                            │    ║
║  │                                                                   │    ║
║  │    CVEs: CVE-2026-43074 (RCU), CVE-2026-46242 (UAF)              │    ║
║  └──────────────────────────────────────────────────────────────────┘    ║
║                                                                            ║
║  ┌──────────────────────────────────────────────────────────────────┐    ║
║  │ 3. fanotify (File Activity Notification) - 5% workload           │    ║
║  │    • Filesystem event monitoring                                 │    ║
║  │    • Permission checking (can block file access)                 │    ║
║  │    • Works across ALL filesystems                                │    ║
║  │                                                                   │    ║
║  │    System Calls:                                                 │    ║
║  │    ┌─────────────────────────────────────────────────────┐      │    ║
║  │    │ fanotify_init()  → Initialize                       │      │    ║
║  │    │ fanotify_mark()  → Mark files/dirs to monitor       │      │    ║
║  │    │ read()           → Read events                      │      │    ║
║  │    └─────────────────────────────────────────────────────┘      │    ║
║  │                                                                   │    ║
║  │    Use Cases:                                                     │    ║
║  │    • Antivirus real-time scanning                                │    ║
║  │    • Backup/indexing daemons                                     │    ║
║  │    • Access control enforcement                                  │    ║
║  │                                                                   │    ║
║  │    Events:                                                        │    ║
║  │    • FAN_ACCESS, FAN_MODIFY, FAN_OPEN, FAN_CLOSE                │    ║
║  │    • FAN_OPEN_PERM (can allow/deny access)                      │    ║
║  │                                                                   │    ║
║  │    CVEs: CVE-2026-46150 (false positive permission events)       │    ║
║  └──────────────────────────────────────────────────────────────────┘    ║
║                                                                            ║
║  ┌──────────────────────────────────────────────────────────────────┐    ║
║  │ 4. VFS Generic Infrastructure - 2% workload                      │    ║
║  │    • Cross-cutting FS utilities                                  │    ║
║  │    • Common helpers used by all filesystems                      │    ║
║  │    • File locking mechanisms                                     │    ║
║  │                                                                   │    ║
║  │    CVEs: CVE-2026-43158 (XFS freemap - generic handling)         │    ║
║  └──────────────────────────────────────────────────────────────────┘    ║
║                                                                            ║
║  ┌──────────────────────────────────────────────────────────────────┐    ║
║  │ 5. Other Kernel FS Subsystems - 41% workload                     │    ║
║  │    • rxrpc (RxRPC network protocol for AFS)                      │    ║
║  │    • UDF (Universal Disk Format for DVDs/CDs)                    │    ║
║  │    • Some CIFS/SMB client issues (might belong in FS-Net)        │    ║
║  │                                                                   │    ║
║  │    CVEs: CVE-2026-23066, CVE-2026-45998, CVE-2026-45991          │    ║
║  └──────────────────────────────────────────────────────────────────┘    ║
╚═══════════════════════════════════════════════════════════════════════════╝
```

---

## 🏗️ COMPONENT INTERACTION DIAGRAM

```
                      USER SPACE
                          │
    ┌─────────────────────┼─────────────────────┐
    │                     │                     │
    ▼                     ▼                     ▼
┌────────┐          ┌──────────┐          ┌──────────┐
│  read  │          │  epoll   │          │ fanotify │
│ /proc/ │          │  _wait() │          │  _mark() │
└────┬───┘          └─────┬────┘          └─────┬────┘
     │                    │                     │
     │  syscall           │  syscall            │  syscall
     ▼                    ▼                     ▼
┌─────────────────────────────────────────────────────────┐
│              KERNEL SPACE (VFS Layer)                    │
└─────────────────────────────────────────────────────────┘
     │                    │                     │
     ▼                    ▼                     ▼
┌──────────┐       ┌───────────┐         ┌──────────────┐
│  procfs  │       │ eventpoll │         │   fanotify   │
│          │       │           │         │              │
│ ┌──────┐ │       │ ┌───────┐ │         │  ┌────────┐  │
│ │ /proc│ │       │ │ epoll │ │         │  │FS Event│  │
│ │ /[pid│ │       │ │ wait  │ │         │  │Monitor │  │
│ │  ]/  │ │       │ │ queue │ │         │  │        │  │
│ └──┬───┘ │       │ └───┬───┘ │         │  └────┬───┘  │
│    │     │       │     │     │         │       │      │
│    │ RCU │       │     │ RCU │         │       │      │
│    │ safe│       │     │grace│         │       │      │
│    │     │       │     │pd   │         │       │      │
└────┼─────┘       └─────┼─────┘         └───────┼──────┘
     │                   │                       │
     │                   │                       │
     │                   ▼                       ▼
     │            ┌─────────────┐     ┌──────────────────┐
     │            │ File/Socket │     │  ALL Filesystems │
     │            │ Descriptors │     │  • ext4          │
     │            │             │     │  • XFS           │
     │            │ ┌─────────┐ │     │  • NFS           │
     │            │ │ File 1  │ │     │  • CIFS          │
     │            │ │ File 2  │ │     │  • etc.          │
     │            │ │ Socket  │ │     │                  │
     │            │ │   ...   │ │     │ (generates events│
     │            │ └─────────┘ │     │  for monitoring) │
     │            └─────────────┘     └──────────────────┘
     │
     ▼
┌──────────────┐
│Process Table │
│Task Structs  │
│Memory Info   │
│System Stats  │
└──────────────┘


LEGEND:
═══════  FS (General) components
───────  Standard kernel infrastructure
```

---

## 🎯 KEY RELATIONSHIPS

### **procfs sits ABOVE the process/system data**
```
/proc/[pid]/status ──reads──> task_struct in kernel
/proc/meminfo ──reads──> kernel memory stats
/proc/cpuinfo ──reads──> CPU data structures
```

### **eventpoll sits ALONGSIDE file operations**
```
Application ──epoll_wait()──> eventpoll subsystem ──monitors──> File descriptors
                                                              └──monitors──> Sockets
```

### **fanotify sits ACROSS all filesystems**
```
Filesystem Operation (open/read/write)
         │
         ├──> Normal path to filesystem
         │
         └──> Triggers fanotify event ──> Monitoring application
                                           (can allow/deny)
```

### **VFS Generic code is USED BY all filesystems**
```
ext4 ──uses──┐
XFS  ──uses──┤
NFS  ──uses──┼──> VFS generic helpers (locking, caching, etc.)
CIFS ──uses──┤
GFS2 ──uses──┘
```

---

## 📦 FS TEAMS MAPPING TO STACK

| Stack Layer | FS Team | Examples |
|-------------|---------|----------|
| **VFS Core** | FS-VFS | Inode/dentry cache, VFS operations |
| **procfs, epoll, fanotify** | **FS (General)** | Pseudo-filesystems, event mechanisms |
| **Local Filesystems** | FS-local | ext4, XFS, Btrfs |
| **Network Filesystems** | FS-Net | NFS, CIFS, SMB |
| **Cluster Filesystems** | FS-GFS2 | GFS2 |

---

## 🔍 WHY FS (GENERAL) IS UNIQUE

1. **No Physical Storage Backend**
   - procfs, sysfs are purely virtual
   - Data comes from kernel memory structures

2. **Cross-Cutting Infrastructure**
   - eventpoll works with ALL file types
   - fanotify monitors ALL filesystems

3. **Performance Critical**
   - epoll is THE mechanism for high-performance servers
   - procfs is read constantly by monitoring tools

4. **Security Sensitive**
   - UAF vulnerabilities in epoll can compromise system
   - procfs info leaks can expose sensitive data
   - fanotify bugs can bypass access controls

---

**Generated:** June 05, 2026  
**For:** FS Teams Daily Digest Documentation  
**Contact:** Anand Reddy (anareddy@redhat.com)
