# FS (General) / rhel-fs Team - Component Summary

**Generated:** June 05, 2026  
**Team Jira Value:** `rhel-fs`  
**Report Section:** FS (General) (positioned at end of daily digest)

---

## 📊 Current Workload

- **Total Active Issues:** 59
- **Active CVEs:** 49 (83% of workload)
- **Bugs:** 1
- **Stories:** 3
- **Unique CVE Vulnerabilities:** 10

---

## 🎯 What Components Does FS (General) Cover?

The **FS (General)** team handles **cross-cutting filesystem infrastructure** and **kernel subsystems** that don't belong to a specific filesystem implementation. This is a **catch-all team** for generic Linux kernel filesystem-related work.

### **Primary Component Areas:**

### 1. **procfs (Process Filesystem)** - ~25% of workload
**Purpose:** Virtual filesystem providing process and system information  
**Location:** `/proc` directory

**Responsibilities:**
- Process information exports (`/proc/[pid]/`)
- System information (`/proc/cpuinfo`, `/proc/meminfo`)
- Kernel tunables (`/proc/sys/`)
- RCU protection for process tree navigation

**Recent CVEs:**
- CVE-2026-46259: procfs RCU protection issues (13 versions affected)
- CVE-2025-38653: proc_lseek consistency checks

---

### 2. **eventpoll/epoll (Event Polling Mechanism)** - ~27% of workload
**Purpose:** Scalable I/O event notification mechanism  
**System Calls:** `epoll_create()`, `epoll_wait()`, `epoll_ctl()`

**Responsibilities:**
- Event polling infrastructure for high-performance applications
- File descriptor monitoring
- Use-after-free (UAF) protection
- RCU grace period management

**Recent CVEs:**
- CVE-2026-43074: eventpoll RCU grace period issues (9 versions affected)
- CVE-2026-46242: ep_remove UAF vulnerabilities (7 versions affected)

**Impact:** Critical for web servers, databases, and high-performance applications using async I/O

---

### 3. **fanotify (File Activity Notification)** - ~5% of workload
**Purpose:** Filesystem event monitoring and permission checking  
**Use Cases:** Anti-virus software, backup tools, access control

**Responsibilities:**
- File access monitoring
- Permission event handling
- False positive prevention in event generation

**Recent CVEs:**
- CVE-2026-46150: False positive on permission events (1 version affected)

---

### 4. **VFS (Virtual Filesystem) / Generic FS Infrastructure** - ~2% of workload
**Purpose:** Common filesystem abstraction layer

**Responsibilities:**
- Inode management
- Dentry cache
- File locking mechanisms
- Generic filesystem utilities

**Recent CVEs:**
- CVE-2026-43158: XFS freemap adjustments (affects XFS but handled generically)

---

### 5. **Other Cross-Cutting Concerns** - ~41% of workload

**Network Filesystems:**
- CVE-2026-23066: rxrpc (RxRPC protocol - used by AFS network filesystem)
- CVE-2026-45998: rxrpc UAF issues

**SMB/CIFS Client:**
- CVE-2026-46243: CIFS userspace credential rejection (should possibly be in FS-Net)

**UDF (Universal Disk Format):**
- CVE-2026-45991: UDF partition descriptor bookkeeping

---

## 🔍 Why "rhel-fs" vs Specific Teams?

Issues land in **FS (General)** when they:

1. **Cross multiple filesystems** - Generic VFS/kernel infrastructure
2. **Don't map to a specific team** - procfs, epoll, fanotify
3. **Are waiting for triage** - Need proper team assignment
4. **Affect kernel core subsystems** - Event handling, process management
5. **Are catch-all assignments** - Default when specific team unclear

---

## 📈 Key Characteristics

### **High CVE Concentration**
- 83% of workload is security vulnerabilities
- Many CVEs affect multiple RHEL versions (up to 13 versions)
- Focus on kernel infrastructure means high severity/impact

### **Cross-Version Impact**
Most CVEs in this team affect **many RHEL versions** simultaneously:
- CVE-2026-46259 (procfs): **13 versions**
- CVE-2026-43074 (eventpoll): **9 versions**
- CVE-2026-46242 (eventpoll): **7 versions**

### **Current Team Members**
Based on active assignments:
- **FS Maint** (maintenance team - handles most issues)
- **Arif Badar** (active contributor)

---

## 🎯 Relationship to Other FS Teams

| Team | Focus | Overlap with FS (General) |
|------|-------|---------------------------|
| **FS-Net** | NFS, CIFS, SMB | Some CIFS/SMB issues appear in both |
| **FS-local** | ext4, XFS, Btrfs | Generic VFS work affects local FS |
| **FS-VFS** | VFS layer | Direct overlap - some triage needed |
| **FS-GFS2** | GFS2, cluster FS | Minimal overlap |

---

## 🚨 Potential Issues & Recommendations

### **Issue 1: Team Assignment Ambiguity**
Some issues seem miscategorized:
- **CVE-2026-46243** (SMB client) - Should be **FS-Net**?
- **CVE-2026-43158** (XFS) - Should be **FS-local**?

**Recommendation:** Review and reassign to specific teams where appropriate.

### **Issue 2: High CVE Backlog**
49 active CVEs is significant, especially with multi-version impact.

**Recommendation:** 
- Prioritize by severity and RHEL version criticality
- Consider additional resources for procfs/eventpoll work

### **Issue 3: Maintenance Team Dependency**
Heavy reliance on "FS Maint" generic assignment.

**Recommendation:**
- Identify individual assignees for active work
- Track capacity of FS Maint team

---

## 💡 Summary

**FS (General) / rhel-fs** is a **critical infrastructure team** handling:

1. **Core kernel filesystem subsystems** (procfs, eventpoll, fanotify)
2. **Cross-cutting VFS work** affecting all filesystems
3. **Catch-all assignments** needing triage
4. **High-impact CVEs** with multi-version scope

**Primary Value:**
- Ensures no FS-related work falls through the cracks
- Handles infrastructure that doesn't fit specific FS team mandates
- Provides visibility into kernel core FS subsystem work

**Addition to Daily Digest:**
- Previously **invisible** 49 CVEs now tracked
- Critical for complete FS team health assessment
- Positioned at end to maintain focus on specific FS teams first

---

**Contact:** Anand Reddy (anareddy@redhat.com)  
**Dashboard:** [FS Team Dashboard](https://redhat.atlassian.net/jira/dashboards/25063)
