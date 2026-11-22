"""Rule catalog. One place that maps every escape primitive to its risk,
the CVEs it enables or amplifies, and how to fix it."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

RUNC_NOV_2025 = ["CVE-2025-31133", "CVE-2025-52565", "CVE-2025-52881"]
NVIDIASCAPE = ["CVE-2025-23266"]

CVE_INFO = {
    "CVE-2025-31133": {
        "name": "runc maskedPaths /dev/null symlink race",
        "summary": "A container image or config that swaps /dev/null for a symlink during "
        "container creation makes runc bind-mount an attacker chosen procfs file read-write "
        "(for example /proc/sys/kernel/core_pattern), which leads to host code execution.",
        "fixed_in": "runc 1.2.8, 1.3.3, 1.4.0-rc.3",
        "url": "https://github.com/opencontainers/runc/security/advisories/GHSA-9493-h29p-rfm2",
    },
    "CVE-2025-52565": {
        "name": "runc /dev/console bind mount race",
        "summary": "A race on the /dev/console bind mount lets a malicious container redirect "
        "the mount to a procfs path and gain write access to host kernel knobs.",
        "fixed_in": "runc 1.2.8, 1.3.3, 1.4.0-rc.3",
        "url": "https://github.com/opencontainers/runc/security/advisories/GHSA-qw9x-cqr3-wc7r",
    },
    "CVE-2025-52881": {
        "name": "runc LSM bypass via misdirected procfs writes",
        "summary": "Shared mounts and racing symlinks redirect runc's own writes (for example "
        "AppArmor labels in /proc/self/attr) to other procfs files such as /proc/sysrq-trigger, "
        "bypassing LSM confinement and enabling host DoS or escape.",
        "fixed_in": "runc 1.2.8, 1.3.3, 1.4.0-rc.3",
        "url": "https://github.com/opencontainers/runc/security/advisories/GHSA-cgrx-mc8f-2prm",
    },
    "CVE-2025-23266": {
        "name": "NVIDIAScape, NVIDIA Container Toolkit LD_PRELOAD hook escape",
        "summary": "The toolkit's createContainer OCI hook inherits environment variables from "
        "the container image. An image that sets LD_PRELOAD makes the privileged hook load an "
        "attacker library on the host, giving root on the GPU node.",
        "fixed_in": "NVIDIA Container Toolkit 1.17.8, GPU Operator 25.3.2",
        "url": "https://nvidia.custhelp.com/app/answers/detail/a_id/5659",
    },
}


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    description: str
    remediation: str
    cves: List[str] = field(default_factory=list)
    # keys into the kyverno / falco generators
    kyverno: str = ""
    falco: List[str] = field(default_factory=list)


RULES: Dict[str, Rule] = {}


def _r(rule: Rule) -> None:
    RULES[rule.id] = rule


_r(Rule("EA001", "Privileged container", "critical",
        "--privileged disables almost every isolation boundary: all capabilities, all host "
        "devices, writable /proc/sys and /sys, no seccomp and no AppArmor. Host escape is a "
        "few shell commands away (core_pattern, cgroup release_agent, raw disk mount).",
        "Remove privileged mode. Grant only the specific capability or device the workload needs.",
        RUNC_NOV_2025, kyverno="privileged",
        falco=["core_pattern_write", "release_agent_write", "container_mount", "sysrq_write"]))
_r(Rule("EA002", "Dangerous Linux capability added", "high",
        "Capabilities such as SYS_ADMIN, SYS_MODULE, DAC_READ_SEARCH, SYS_PTRACE, SYS_RAWIO and "
        "BPF each enable a known escape path (mounting, kernel module load, open_by_handle_at, "
        "process injection, raw IO, eBPF).",
        "Drop ALL capabilities and add back only what is required. Never add SYS_ADMIN or SYS_MODULE.",
        [], kyverno="capabilities", falco=["container_mount", "kernel_module_load"]))
_r(Rule("EA003", "Container runtime socket mounted", "critical",
        "A mounted docker.sock, containerd.sock or crio.sock gives full control of the runtime. "
        "Anyone in the container can start a new privileged container with the host root "
        "mounted. This is the primitive abused by Docker API cryptojacking campaigns.",
        "Do not mount runtime sockets. Use a scoped API proxy or a dedicated build service instead.",
        [], kyverno="runtime_socket", falco=["runtime_socket_access"]))
_r(Rule("EA004", "Host root filesystem mounted", "critical",
        "The host / is bind mounted into the container. Writing to it is equivalent to root on the host.",
        "Mount only the exact host directory the workload needs, read-only where possible.",
        [], kyverno="host_path", falco=["host_sensitive_write"]))
_r(Rule("EA005", "Sensitive host path mounted", "high",
        "Host /proc, /sys, /etc, /dev, /root, /boot, /lib/modules, /var/lib/docker or similar is "
        "mounted. These expose kernel knobs, credentials or other containers' filesystems.",
        "Remove the hostPath mount or replace it with a projected volume or a narrow read-only path.",
        [], kyverno="host_path", falco=["host_sensitive_write"]))
_r(Rule("EA006", "Host PID namespace shared", "high",
        "With the host PID namespace the container sees every host process and can reach host "
        "filesystems through /proc/<pid>/root, or inject into processes with ptrace.",
        "Remove pid: host / hostPID: true.",
        [], kyverno="host_namespaces", falco=["proc_root_access"]))
_r(Rule("EA007", "Host network namespace shared", "medium",
        "The container shares the host network stack and can reach services bound to localhost "
        "on the host, including unauthenticated runtime or kubelet APIs.",
        "Remove network_mode: host / hostNetwork: true.", [], kyverno="host_namespaces"))
_r(Rule("EA008", "Host IPC namespace shared", "medium",
        "Shared host IPC exposes host shared memory segments and semaphores.",
        "Remove ipc: host / hostIPC: true.", [], kyverno="host_namespaces"))
_r(Rule("EA009", "AppArmor disabled (unconfined)", "high",
        "Without AppArmor the container loses the default deny rules for mount, /proc/sys writes "
        "and other escape steps. Note that CVE-2025-52881 shows LSM labels alone are not enough.",
        "Use the default docker-default or runtime/default AppArmor profile.",
        ["CVE-2025-52881"], kyverno="apparmor"))
_r(Rule("EA010", "Seccomp disabled (unconfined)", "high",
        "Without seccomp, syscalls such as mount, unshare, keyctl, bpf, open_by_handle_at and "
        "init_module are reachable from the container.",
        "Use the RuntimeDefault seccomp profile or a stricter custom profile.",
        [], kyverno="seccomp", falco=["container_mount"]))
_r(Rule("EA011", "Host device exposed", "high",
        "Host block or character devices are passed through. Raw disk access lets a container "
        "read or modify the host filesystem directly.",
        "Remove the device mapping. Use a device plugin with a narrow device if hardware is required.",
        [], kyverno="privileged", falco=["raw_disk_read"]))
_r(Rule("EA012", "Host cgroup namespace or writable cgroupfs", "medium",
        "A host cgroup namespace or writable /sys/fs/cgroup makes the cgroup v1 release_agent "
        "escape reachable when combined with SYS_ADMIN.",
        "Use a private cgroup namespace (the default on cgroup v2) and never mount cgroupfs read-write.",
        [], falco=["release_agent_write"]))
_r(Rule("EA013", "Root in container without user namespace", "medium",
        "UID 0 in the container is UID 0 on the host. User namespaces (rootless or userns-remap) "
        "are the main mitigation for the November 2025 runc escapes because the remapped root "
        "cannot write host procfs files.",
        "Run as a non-root USER, and enable user namespaces (rootless Docker, userns-remap, or "
        "Kubernetes hostUsers: false).",
        RUNC_NOV_2025, kyverno="run_as_non_root"))
_r(Rule("EA014", "no-new-privileges not set", "low",
        "Setuid binaries inside the container can still raise privileges.",
        "Set security_opt: no-new-privileges:true or allowPrivilegeEscalation: false.",
        [], kyverno="privilege_escalation"))
_r(Rule("EA015", "runc vulnerable to November 2025 escapes", "critical",
        "The host runc version is older than the fixed releases for CVE-2025-31133, "
        "CVE-2025-52565 and CVE-2025-52881. A malicious image or container config can escape.",
        "Upgrade runc to 1.2.8, 1.3.3, 1.4.0-rc.3 or later and enable user namespaces.",
        RUNC_NOV_2025, falco=["core_pattern_write", "sysrq_write"]))
_r(Rule("EA016", "NVIDIA Container Toolkit vulnerable to NVIDIAScape", "critical",
        "The NVIDIA Container Toolkit on this host is older than 1.17.8. Any image that sets "
        "LD_PRELOAD can take over the host through the createContainer hook.",
        "Upgrade to NVIDIA Container Toolkit 1.17.8 or later. As a stopgap set "
        "features.disable-cuda-compat-lib-hook = true in /etc/nvidia-container-runtime/config.toml.",
        NVIDIASCAPE, falco=["nvidia_hook_preload"]))
_r(Rule("EA017", "LD_PRELOAD set in image or container environment", "high",
        "LD_PRELOAD in an image ENV is the exact trigger for NVIDIAScape on GPU hosts, and is a "
        "strong signal of a weaponized image elsewhere.",
        "Remove LD_PRELOAD from the image. Block it in admission policy for GPU workloads.",
        NVIDIASCAPE, kyverno="ld_preload", falco=["nvidia_hook_preload"]))
_r(Rule("EA018", "GPU workload on NVIDIA runtime", "info",
        "The workload requests NVIDIA GPUs, so the NVIDIA Container Toolkit hooks run for it on the host.",
        "Keep the toolkit patched (>= 1.17.8) and only allow trusted images on GPU nodes.",
        NVIDIASCAPE))
_r(Rule("EA019", "Image ships device or procfs symlinks", "critical",
        "The image filesystem contains a symlink at a /dev path or a symlink that points into "
        "/proc. This is the setup step for the runc mount races (CVE-2025-31133, CVE-2025-52565).",
        "Do not run this image. Rebuild from a trusted base and upgrade runc.",
        ["CVE-2025-31133", "CVE-2025-52565"]))
_r(Rule("EA020", "Build step tampers with /dev or /proc", "high",
        "A RUN instruction creates or replaces entries under /dev or links into /proc. Legit "
        "images almost never do this. It matches the runc mount race setup.",
        "Remove the instruction. Review where this Dockerfile came from.",
        ["CVE-2025-31133", "CVE-2025-52565"]))
_r(Rule("EA021", "Insecure BuildKit entitlement", "high",
        "RUN --security=insecure runs the build step fully privileged on the build host. Any "
        "build service that accepts untrusted Dockerfiles can be escaped this way.",
        "Remove --security=insecure and do not grant the security.insecure entitlement to builders.",
        []))
_r(Rule("EA022", "User namespace explicitly disabled", "medium",
        "userns_mode: host opts this container out of daemon user namespace remapping.",
        "Remove userns_mode: host.", RUNC_NOV_2025))
_r(Rule("EA023", "Runtime socket writable by non-root on host", "high",
        "The Docker socket on the host is group or world writable. Any member of that group "
        "is effectively root.",
        "Restrict socket permissions and audit the docker group, or use rootless Docker.",
        []))
_r(Rule("EA024", "Host daemon has no user namespace isolation", "medium",
        "The container engine runs rootful without userns-remap, so container root maps to "
        "host root for every workload.",
        "Enable userns-remap or run rootless Docker or Podman.",
        RUNC_NOV_2025))

_r(Rule("EA025", "Writable host bind mount", "medium",
        "A host directory is bind mounted read-write. Anything written in the container lands on "
        "the host, which is a persistence and tampering path even when the directory looks harmless.",
        "Mount host paths read-only, or use a named volume.",
        [], falco=["host_sensitive_write"]))

DANGEROUS_CAPS = {
    "SYS_ADMIN": "critical",
    "SYS_MODULE": "critical",
    "DAC_READ_SEARCH": "high",
    "SYS_PTRACE": "high",
    "SYS_RAWIO": "high",
    "BPF": "high",
    "SYS_BOOT": "high",
    "PERFMON": "medium",
    "DAC_OVERRIDE": "medium",
    "NET_ADMIN": "medium",
    "SYSLOG": "low",
    "MKNOD": "low",
    "ALL": "critical",
}

CAP_REASON = {
    "SYS_ADMIN": "mount, cgroup release_agent, many kernel interfaces",
    "SYS_MODULE": "load a kernel module and run code in ring 0",
    "DAC_READ_SEARCH": "open_by_handle_at host file read (the Shocker exploit)",
    "SYS_PTRACE": "inject into processes, combined with host PID it reaches host processes",
    "SYS_RAWIO": "raw IO ports and /dev/mem style access",
    "BPF": "load eBPF programs that can read kernel memory",
    "SYS_BOOT": "reboot or kexec the host",
    "PERFMON": "perf events that leak kernel data",
    "DAC_OVERRIDE": "bypass file permission checks on mounted host paths",
    "NET_ADMIN": "reconfigure networking, sniff or redirect traffic",
    "SYSLOG": "read kernel log, leak kernel pointers",
    "MKNOD": "create device nodes",
    "ALL": "every capability",
}

RUNTIME_SOCKETS = (
    "/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock",
    "/var/run/containerd/containerd.sock", "/run/crio/crio.sock", "/var/run/crio/crio.sock",
    "/run/podman/podman.sock", "/var/run/cri-dockerd.sock", "/run/k3s/containerd/containerd.sock",
)

SENSITIVE_HOST_PATHS = (
    "/proc", "/sys", "/etc", "/dev", "/root", "/boot", "/lib/modules", "/usr/lib/modules",
    "/var/lib/docker", "/var/lib/containerd", "/var/lib/kubelet", "/var/run", "/run",
    "/home", "/var/log", "/sys/fs/cgroup", "/usr",
)
