# EscapeArmed in-container probe. POSIX sh, works on busybox, dash and bash.
# Every check is read-only or self-cleaning. Nothing here writes to host
# kernel knobs, loads modules, or starts containers.
# Output protocol, one line per result:  EA|<probe>|<STATUS>|<evidence>
# The caller prepends:  EA_TOKEN=...  EA_WRITE_DIRS="..."  EA_READ_ROOTS="..."  EA_SOCKETS="..."

EA_TMP=""
ea_cleanup() {
  if [ -n "$EA_TMP" ]; then
    for d in "$EA_TMP"/m*; do
      [ -d "$d" ] && umount "$d" 2>/dev/null
    done
    rm -rf "$EA_TMP" 2>/dev/null
  fi
}
trap ea_cleanup EXIT INT TERM

out() { printf 'EA|%s|%s|%s\n' "$1" "$2" "$3"; }
have() { command -v "$1" >/dev/null 2>&1; }

EA_TMP=$(mktemp -d /tmp/.escapearmed.XXXXXX 2>/dev/null || { mkdir -p /tmp/.escapearmed.$$ && echo /tmp/.escapearmed.$$; })

# ---------------------------------------------------------------- identity
uid=$(id -u 2>/dev/null || echo "?")
umap=$(head -n1 /proc/self/uid_map 2>/dev/null | tr -s ' ' | sed 's/^ //')
out identity INFO "uid=$uid uid_map=[$umap]"

capeff=$(grep '^CapEff:' /proc/self/status 2>/dev/null | awk '{print $2}')
caps=""
if [ -n "$capeff" ]; then
  for pair in 21:SYS_ADMIN 16:SYS_MODULE 2:DAC_READ_SEARCH 19:SYS_PTRACE 17:SYS_RAWIO 39:BPF 22:SYS_BOOT 12:NET_ADMIN 1:DAC_OVERRIDE; do
    bit=${pair%%:*}; name=${pair#*:}
    if [ $(( (0x$capeff >> bit) & 1 )) -eq 1 ]; then caps="$caps $name"; fi
  done
fi
if [ -n "$caps" ]; then out caps PROVEN "CapEff=$capeff dangerous:$caps"; else out caps BLOCKED "CapEff=$capeff no dangerous caps"; fi

aa=$(cat /proc/self/attr/current 2>/dev/null | tr -d '\0')
sc=$(grep '^Seccomp:' /proc/self/status 2>/dev/null | awk '{print $2}')
out lsm INFO "apparmor=[${aa:-n/a}] seccomp_mode=${sc:-n/a}"

# ---------------------------------------------------------------- runtime socket
ea_http() {
  # $1 socket path. Read-only GET /version against the runtime API.
  s=$1
  if have curl; then
    curl -s -m 5 --unix-socket "$s" http://localhost/version 2>/dev/null && return 0
  fi
  if have perl; then
    perl -MIO::Socket::UNIX -e '
      my $c = IO::Socket::UNIX->new(Peer => $ARGV[0], Type => SOCK_STREAM) or exit 1;
      print $c "GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n";
      local $/; my $r = <$c>; print $r; exit 0' "$s" 2>/dev/null && return 0
  fi
  if have python3; then
    python3 - "$s" <<'PY' 2>/dev/null && return 0
import socket, sys
c = socket.socket(socket.AF_UNIX); c.settimeout(5); c.connect(sys.argv[1])
c.sendall(b"GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n")
print(c.recv(65536).decode(errors="replace"))
PY
  fi
  if have socat; then
    printf 'GET /version HTTP/1.0\r\nHost: localhost\r\n\r\n' | socat - UNIX-CONNECT:"$s" 2>/dev/null && return 0
  fi
  return 2
}

found_sock=0
seen_socks=" "
for s in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock /var/run/containerd/containerd.sock /run/crio/crio.sock /run/podman/podman.sock $EA_SOCKETS; do
  [ -S "$s" ] || continue
  real=$(readlink -f "$s" 2>/dev/null || echo "$s")
  case "$seen_socks" in *" $real "*) continue ;; esac
  seen_socks="$seen_socks$real "
  found_sock=1
  if [ ! -w "$s" ]; then out runtime_socket BLOCKED "$s present but not writable by uid $uid"; continue; fi
  resp=$(ea_http "$s"); rc=$?
  if [ $rc -eq 2 ]; then
    out runtime_socket LIKELY "$s is writable, no client (curl/perl/python3/socat) to confirm API access"
  elif printf '%s' "$resp" | grep -q '"ApiVersion"'; then
    ver=$(printf '%s' "$resp" | sed -n 's/.*"Version":"\([^"]*\)".*/\1/p' | head -n1)
    api=$(printf '%s' "$resp" | sed -n 's/.*"ApiVersion":"\([^"]*\)".*/\1/p' | head -n1)
    out runtime_socket PROVEN "GET /version on $s answered: engine $ver API $api. Full daemon control from inside the container."
  elif [ -n "$resp" ]; then
    out runtime_socket LIKELY "$s answered but not with a Docker API payload (containerd/CRI use gRPC)"
  else
    out runtime_socket BLOCKED "$s did not answer"
  fi
done
[ $found_sock -eq 0 ] && out runtime_socket NA "no runtime socket inside the container"

# ---------------------------------------------------------------- host mount write canary
for d in $EA_WRITE_DIRS; do
  if [ ! -d "$d" ]; then out host_write NA "$d is not a directory"; continue; fi
  f="$d/.escapearmed-canary-$EA_TOKEN"
  if printf 'escapearmed canary %s\n' "$EA_TOKEN" > "$f" 2>/dev/null; then
    out host_write WROTE "$d|$f"
  else
    out host_write BLOCKED "$d not writable by uid $uid"
  fi
done

# ---------------------------------------------------------------- host root / etc read
for r in $EA_READ_ROOTS; do
  hn=""
  for cand in "$r/etc/hostname" "$r/hostname"; do
    [ -r "$cand" ] && hn=$(head -c 64 "$cand" | tr -d '\n') && break
  done
  shadow=no
  for cand in "$r/etc/shadow" "$r/shadow"; do [ -r "$cand" ] && shadow=yes && break; done
  if [ -n "$hn" ]; then out host_read READ "$r|$hn|$shadow"; else out host_read BLOCKED "$r has no readable hostname file"; fi
done

# ---------------------------------------------------------------- host PID namespace
p1=$(cat /proc/1/comm 2>/dev/null)
mns1=$(readlink /proc/1/ns/mnt 2>/dev/null)
mnsself=$(readlink /proc/self/ns/mnt 2>/dev/null)
nprocs=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l | tr -d ' ')
if [ -r /proc/1/root/etc/hostname ] && [ -n "$mns1" ] && [ "$mns1" != "$mnsself" ]; then
  out host_pid READ "/proc/1/root|$(head -c 64 /proc/1/root/etc/hostname | tr -d '\n')|$p1"
elif [ "$p1" = "systemd" ] || [ "$p1" = "init" ] || [ "$nprocs" -gt 60 ]; then
  out host_pid LIKELY "host process tree visible (PID 1 is $p1, $nprocs processes) but /proc/1/root is not readable"
else
  out host_pid BLOCKED "PID 1 is ${p1:-unknown}, $nprocs processes visible, host process tree not reachable"
fi

# ---------------------------------------------------------------- kernel knobs (test only, never written)
if [ -w /proc/sys/kernel/core_pattern ]; then
  out core_pattern PROVEN "/proc/sys/kernel/core_pattern is writable (current: $(head -c 80 /proc/sys/kernel/core_pattern)). Writing a |/path pipe here runs a host binary as root on the next crash. Not written."
else
  out core_pattern BLOCKED "/proc/sys/kernel/core_pattern is read-only"
fi
if [ -w /proc/sysrq-trigger ]; then
  out sysrq PROVEN "/proc/sysrq-trigger is writable, host can be crashed or rebooted from the container. Not written."
else
  out sysrq BLOCKED "/proc/sysrq-trigger is not writable"
fi

# ---------------------------------------------------------------- mount syscall + cgroup release_agent
m1="$EA_TMP/m1"; mkdir -p "$m1"
if mount -t tmpfs -o size=1m escapearmed "$m1" 2>/dev/null; then
  umount "$m1" 2>/dev/null
  out mount PROVEN "mount(2) succeeded for a scratch tmpfs (unmounted)"
else
  out mount BLOCKED "mount(2) denied"
fi

ra=""
for f in /sys/fs/cgroup/release_agent /sys/fs/cgroup/*/release_agent; do
  [ -w "$f" ] && ra="$f" && break
done
if [ -n "$ra" ]; then
  out release_agent PROVEN "existing $ra is writable. Not written."
else
  m2="$EA_TMP/m2"; mkdir -p "$m2"
  if mount -t cgroup -o none,name=escapearmed cgroup "$m2" 2>/dev/null; then
    if [ -w "$m2/release_agent" ]; then
      out release_agent PROVEN "mounted a fresh cgroup v1 hierarchy, release_agent is writable (classic notify_on_release escape). Not written, unmounted."
    else
      out release_agent BLOCKED "cgroup v1 mount allowed but release_agent not writable"
    fi
    umount "$m2" 2>/dev/null
  elif ! grep -qw cgroup /proc/filesystems 2>/dev/null; then
    out release_agent BLOCKED "kernel has no cgroup v1 support and no writable release_agent"
  elif [ "$(readlink /proc/self/ns/cgroup 2>/dev/null)" != "$(readlink /proc/1/ns/cgroup 2>/dev/null)" ] || [ "$EA_CGROUPNS" = "private" ]; then
    out release_agent BLOCKED "new cgroup v1 hierarchy denied (private cgroup namespace), no writable release_agent. Becomes reachable with --cgroupns=host"
  else
    out release_agent BLOCKED "cannot mount a cgroup v1 hierarchy and no writable release_agent"
  fi
fi

# ---------------------------------------------------------------- raw host disk
disk_done=0
for dev in /dev/vda /dev/sda /dev/nvme0n1 /dev/xvda /dev/hda /dev/mmcblk0; do
  [ -b "$dev" ] || continue
  disk_done=1
  if dd if="$dev" of=/dev/null bs=512 count=1 2>/dev/null; then
    out raw_disk PROVEN "read the first sector of host block device $dev (discarded)"
  else
    out raw_disk BLOCKED "$dev present but not readable"
  fi
  break
done
[ $disk_done -eq 0 ] && out raw_disk NA "no host block devices visible"

# ---------------------------------------------------------------- kernel modules
case "$caps" in
  *SYS_MODULE*) out kernel_module LIKELY "CAP_SYS_MODULE is effective, init_module would load host kernel code. Not attempted." ;;
  *) out kernel_module BLOCKED "CAP_SYS_MODULE not effective" ;;
esac

# ---------------------------------------------------------------- NVIDIAScape trigger
if [ -n "$LD_PRELOAD" ]; then
  out ld_preload PROVEN "LD_PRELOAD=$LD_PRELOAD is set in the container environment"
else
  out ld_preload NA "LD_PRELOAD not set"
fi
out done INFO "probe finished"
