package main

import (
	"fmt"
	"strconv"

	"github.com/buger/jsonparser"
)

func main() {

	// crictl pods --name bpfman-daemon-hf5gv -o json
	podInfo := []byte(`{
  "items": [
    {
      "id": "ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99",
      "metadata": {
        "name": "bpfman-daemon-hf5gv",
        "uid": "88c00a72-09fa-4f0b-b2e7-185fcaff3b0d",
        "namespace": "bpfman",
        "attempt": 0
      },
      "state": "SANDBOX_READY",
      "createdAt": "1704391789525984415",
      "labels": {
        "controller-revision-hash": "5d8d8bc6d4",
        "io.kubernetes.pod.name": "bpfman-daemon-hf5gv",
        "io.kubernetes.pod.namespace": "bpfman",
        "io.kubernetes.pod.uid": "88c00a72-09fa-4f0b-b2e7-185fcaff3b0d",
        "name": "bpfman-daemon",
        "pod-template-generation": "1"
      },
      "annotations": {
        "bpfman.io.bpfman.agent.loglevel": "info",
        "bpfman.io.bpfman.loglevel": "debug",
        "kubernetes.io/config.seen": "2024-01-04T18:09:49.190418808Z",
        "kubernetes.io/config.source": "api"
      },
      "runtimeHandler": ""
    }
  ]
}`)

	// crictl ps --name bpfman --pod ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99 -o json
	containerInfo := []byte(`{
  "containers": [
    {
      "id": "c1ed727676f3ac5c652b706e4576d1ff7680dfb3fd2dc60cfd9cc87cca6d7e01",
      "podSandboxId": "ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99",
      "metadata": {
        "name": "bpfman-agent",
        "attempt": 0
      },
      "image": {
        "image": "sha256:443c34d0decd3742e331e52eb6563dd786a26bf862a05f04afa1a731b1b85e76",
        "annotations": {
        },
        "userSpecifiedImage": ""
      },
      "imageRef": "sha256:443c34d0decd3742e331e52eb6563dd786a26bf862a05f04afa1a731b1b85e76",
      "state": "CONTAINER_RUNNING",
      "createdAt": "1704391799426614246",
      "labels": {
        "io.kubernetes.container.name": "bpfman-agent",
        "io.kubernetes.pod.name": "bpfman-daemon-hf5gv",
        "io.kubernetes.pod.namespace": "bpfman",
        "io.kubernetes.pod.uid": "88c00a72-09fa-4f0b-b2e7-185fcaff3b0d"
      },
      "annotations": {
        "io.kubernetes.container.hash": "3260145c",
        "io.kubernetes.container.restartCount": "0",
        "io.kubernetes.container.terminationMessagePath": "/dev/termination-log",
        "io.kubernetes.container.terminationMessagePolicy": "File",
        "io.kubernetes.pod.terminationGracePeriod": "15"
      }
    },
    {
      "id": "ee31cab3b7ff9aa60fc4d686fec84881f79fb4194ccf4eb7dda793db04ad48db",
      "podSandboxId": "ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99",
      "metadata": {
        "name": "bpfman",
        "attempt": 0
      },
      "image": {
        "image": "sha256:4f296bdff30513d83c41007bdb1c0f07fc443382f97d074131e1e7c3c46d257b",
        "annotations": {
        },
        "userSpecifiedImage": ""
      },
      "imageRef": "sha256:4f296bdff30513d83c41007bdb1c0f07fc443382f97d074131e1e7c3c46d257b",
      "state": "CONTAINER_RUNNING",
      "createdAt": "1704391799242101914",
      "labels": {
        "io.kubernetes.container.name": "bpfman",
        "io.kubernetes.pod.name": "bpfman-daemon-hf5gv",
        "io.kubernetes.pod.namespace": "bpfman",
        "io.kubernetes.pod.uid": "88c00a72-09fa-4f0b-b2e7-185fcaff3b0d"
      },
      "annotations": {
        "io.kubernetes.container.hash": "5bc1a944",
        "io.kubernetes.container.restartCount": "0",
        "io.kubernetes.container.terminationMessagePath": "/dev/termination-log",
        "io.kubernetes.container.terminationMessagePolicy": "File",
        "io.kubernetes.pod.terminationGracePeriod": "15"
      }
    }
  ]
}`)

	// crictl inspect -o json c1ed727676f3ac5c652b706e4576d1ff7680dfb3fd2dc60cfd9cc87cca6d7e01
	containerData1 := []byte(`{
  "status": {
    "id": "c1ed727676f3ac5c652b706e4576d1ff7680dfb3fd2dc60cfd9cc87cca6d7e01",
    "metadata": {
      "attempt": 0,
      "name": "bpfman-agent"
    },
    "state": "CONTAINER_RUNNING",
    "createdAt": "2024-01-04T18:09:59.426614246Z",
    "startedAt": "2024-01-04T18:09:59.584172387Z",
    "finishedAt": "0001-01-01T00:00:00Z",
    "exitCode": 0,
    "image": {
      "annotations": {},
      "image": "quay.io/bpfman/bpfman-agent:latest",
      "userSpecifiedImage": ""
    },
    "imageRef": "docker.io/library/import-2024-01-04@sha256:db4ac7a840dfb22fb9e1aa879671b26a04990d0c07f7d2a3307407e45c1eda6e",
    "reason": "",
    "message": "",
    "labels": {
      "io.kubernetes.container.name": "bpfman-agent",
      "io.kubernetes.pod.name": "bpfman-daemon-hf5gv",
      "io.kubernetes.pod.namespace": "bpfman",
      "io.kubernetes.pod.uid": "88c00a72-09fa-4f0b-b2e7-185fcaff3b0d"
    },
    "annotations": {
      "io.kubernetes.container.hash": "3260145c",
      "io.kubernetes.container.restartCount": "0",
      "io.kubernetes.container.terminationMessagePath": "/dev/termination-log",
      "io.kubernetes.container.terminationMessagePolicy": "File",
      "io.kubernetes.pod.terminationGracePeriod": "15"
    },
    "mounts": [
      {
        "containerPath": "/run/bpfman/sock",
        "gidMappings": [],
        "hostPath": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volumes/kubernetes.io~empty-dir/bpfman-sock",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/etc/bpfman/bpfman.toml",
        "gidMappings": [],
        "hostPath": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volume-subpaths/bpfman-config/bpfman-agent/1",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": true,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/run/containerd/containerd.sock",
        "gidMappings": [],
        "hostPath": "/run/containerd/containerd.sock",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/run/crio/crio.sock",
        "gidMappings": [],
        "hostPath": "/run/crio/crio.sock",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/var/run/dockershim.sock",
        "gidMappings": [],
        "hostPath": "/var/run/dockershim.sock",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/var/run/cri-dockerd.sock",
        "gidMappings": [],
        "hostPath": "/var/run/cri-dockerd.sock",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/etc/crictl.yaml",
        "gidMappings": [],
        "hostPath": "/etc/crictl.yaml",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/var/run/secrets/kubernetes.io/serviceaccount",
        "gidMappings": [],
        "hostPath": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volumes/kubernetes.io~projected/kube-api-access-tmkmd",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": true,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/etc/hosts",
        "gidMappings": [],
        "hostPath": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/etc-hosts",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/dev/termination-log",
        "gidMappings": [],
        "hostPath": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/containers/bpfman-agent/26cf34d0",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      }
    ],
    "logPath": "/var/log/pods/bpfman_bpfman-daemon-hf5gv_88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/bpfman-agent/0.log",
    "resources": {
      "linux": {
        "cpuPeriod": "100000",
        "cpuQuota": "0",
        "cpuShares": "2",
        "cpusetCpus": "",
        "cpusetMems": "",
        "hugepageLimits": [],
        "memoryLimitInBytes": "0",
        "memorySwapLimitInBytes": "0",
        "oomScoreAdj": "1000",
        "unified": {}
      },
      "windows": null
    }
  },
  "info": {
    "sandboxID": "ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99",
    "pid": 2357,
    "removing": false,
    "snapshotKey": "c1ed727676f3ac5c652b706e4576d1ff7680dfb3fd2dc60cfd9cc87cca6d7e01",
    "snapshotter": "overlayfs",
    "runtimeType": "io.containerd.runc.v2",
    "runtimeOptions": {
      "systemd_cgroup": true
    },
    "config": {
      "metadata": {
        "name": "bpfman-agent"
      },
      "image": {
        "image": "sha256:443c34d0decd3742e331e52eb6563dd786a26bf862a05f04afa1a731b1b85e76"
      },
      "command": [
        "/bpfman-agent"
      ],
      "envs": [
        {
          "key": "KUBE_NODE_NAME",
          "value": "bpfman-deployment-control-plane"
        },
        {
          "key": "GO_LOG",
          "value": "info"
        },
        {
          "key": "KUBERNETES_SERVICE_PORT",
          "value": "443"
        },
        {
          "key": "KUBERNETES_PORT_443_TCP",
          "value": "tcp://10.96.0.1:443"
        },
        {
          "key": "KUBERNETES_PORT_443_TCP_PROTO",
          "value": "tcp"
        },
        {
          "key": "KUBERNETES_PORT_443_TCP_PORT",
          "value": "443"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_PORT_HTTPS",
          "value": "8443"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP",
          "value": "tcp://10.96.207.4:8443"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_PROTO",
          "value": "tcp"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_PORT",
          "value": "8443"
        },
        {
          "key": "KUBERNETES_PORT",
          "value": "tcp://10.96.0.1:443"
        },
        {
          "key": "KUBERNETES_PORT_443_TCP_ADDR",
          "value": "10.96.0.1"
        },
        {
          "key": "KUBERNETES_SERVICE_HOST",
          "value": "10.96.0.1"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_PORT",
          "value": "8443"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT",
          "value": "tcp://10.96.207.4:8443"
        },
        {
          "key": "KUBERNETES_SERVICE_PORT_HTTPS",
          "value": "443"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_HOST",
          "value": "10.96.207.4"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_ADDR",
          "value": "10.96.207.4"
        }
      ],
      "mounts": [
        {
          "container_path": "/run/bpfman/sock",
          "host_path": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volumes/kubernetes.io~empty-dir/bpfman-sock"
        },
        {
          "container_path": "/etc/bpfman/bpfman.toml",
          "host_path": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volume-subpaths/bpfman-config/bpfman-agent/1",
          "readonly": true
        },
        {
          "container_path": "/run/containerd/containerd.sock",
          "host_path": "/run/containerd/containerd.sock"
        },
        {
          "container_path": "/run/crio/crio.sock",
          "host_path": "/run/crio/crio.sock"
        },
        {
          "container_path": "/var/run/dockershim.sock",
          "host_path": "/var/run/dockershim.sock"
        },
        {
          "container_path": "/var/run/cri-dockerd.sock",
          "host_path": "/var/run/cri-dockerd.sock"
        },
        {
          "container_path": "/etc/crictl.yaml",
          "host_path": "/etc/crictl.yaml"
        },
        {
          "container_path": "/var/run/secrets/kubernetes.io/serviceaccount",
          "host_path": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volumes/kubernetes.io~projected/kube-api-access-tmkmd",
          "readonly": true
        },
        {
          "container_path": "/etc/hosts",
          "host_path": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/etc-hosts"
        },
        {
          "container_path": "/dev/termination-log",
          "host_path": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/containers/bpfman-agent/26cf34d0"
        }
      ],
      "labels": {
        "io.kubernetes.container.name": "bpfman-agent",
        "io.kubernetes.pod.name": "bpfman-daemon-hf5gv",
        "io.kubernetes.pod.namespace": "bpfman",
        "io.kubernetes.pod.uid": "88c00a72-09fa-4f0b-b2e7-185fcaff3b0d"
      },
      "annotations": {
        "io.kubernetes.container.hash": "3260145c",
        "io.kubernetes.container.restartCount": "0",
        "io.kubernetes.container.terminationMessagePath": "/dev/termination-log",
        "io.kubernetes.container.terminationMessagePolicy": "File",
        "io.kubernetes.pod.terminationGracePeriod": "15"
      },
      "log_path": "bpfman-agent/0.log",
      "linux": {
        "resources": {
          "cpu_period": 100000,
          "cpu_shares": 2,
          "oom_score_adj": 1000,
          "hugepage_limits": [
            {
              "page_size": "2MB"
            },
            {
              "page_size": "1GB"
            }
          ]
        },
        "security_context": {
          "privileged": true,
          "namespace_options": {
            "network": 2,
            "pid": 1
          },
          "run_as_user": {},
          "supplemental_groups": [
            2000
          ],
          "masked_paths": [
            "/proc/asound",
            "/proc/acpi",
            "/proc/kcore",
            "/proc/keys",
            "/proc/latency_stats",
            "/proc/timer_list",
            "/proc/timer_stats",
            "/proc/sched_debug",
            "/proc/scsi",
            "/sys/firmware"
          ],
          "readonly_paths": [
            "/proc/bus",
            "/proc/fs",
            "/proc/irq",
            "/proc/sys",
            "/proc/sysrq-trigger"
          ],
          "seccomp": {
            "profile_type": 1
          }
        }
      }
    },
    "runtimeSpec": {
      "ociVersion": "1.1.0-rc.1",
      "process": {
        "user": {
          "uid": 0,
          "gid": 0,
          "additionalGids": [
            0,
            2000
          ]
        },
        "args": [
          "/bpfman-agent"
        ],
        "env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "HOSTNAME=bpfman-deployment-control-plane",
          "DISTTAG=f38container",
          "FGC=f38",
          "FBR=f38",
          "KUBE_NODE_NAME=bpfman-deployment-control-plane",
          "GO_LOG=info",
          "KUBERNETES_SERVICE_PORT=443",
          "KUBERNETES_PORT_443_TCP=tcp://10.96.0.1:443",
          "KUBERNETES_PORT_443_TCP_PROTO=tcp",
          "KUBERNETES_PORT_443_TCP_PORT=443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_PORT_HTTPS=8443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP=tcp://10.96.207.4:8443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_PROTO=tcp",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_PORT=8443",
          "KUBERNETES_PORT=tcp://10.96.0.1:443",
          "KUBERNETES_PORT_443_TCP_ADDR=10.96.0.1",
          "KUBERNETES_SERVICE_HOST=10.96.0.1",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_PORT=8443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT=tcp://10.96.207.4:8443",
          "KUBERNETES_SERVICE_PORT_HTTPS=443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_HOST=10.96.207.4",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_ADDR=10.96.207.4"
        ],
        "cwd": "/",
        "capabilities": {
          "bounding": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
            "CAP_PERFMON",
            "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE"
          ],
          "effective": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
            "CAP_PERFMON",
            "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE"
          ],
          "permitted": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
            "CAP_PERFMON",
            "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE"
          ]
        },
        "oomScoreAdj": 1000
      },
      "root": {
        "path": "rootfs"
      },
      "mounts": [
        {
          "destination": "/proc",
          "type": "proc",
          "source": "proc",
          "options": [
            "nosuid",
            "noexec",
            "nodev"
          ]
        },
        {
          "destination": "/dev",
          "type": "tmpfs",
          "source": "tmpfs",
          "options": [
            "nosuid",
            "strictatime",
            "mode=755",
            "size=65536k"
          ]
        },
        {
          "destination": "/dev/pts",
          "type": "devpts",
          "source": "devpts",
          "options": [
            "nosuid",
            "noexec",
            "newinstance",
            "ptmxmode=0666",
            "mode=0620",
            "gid=5"
          ]
        },
        {
          "destination": "/dev/mqueue",
          "type": "mqueue",
          "source": "mqueue",
          "options": [
            "nosuid",
            "noexec",
            "nodev"
          ]
        },
        {
          "destination": "/sys",
          "type": "sysfs",
          "source": "sysfs",
          "options": [
            "nosuid",
            "noexec",
            "nodev",
            "rw"
          ]
        },
        {
          "destination": "/sys/fs/cgroup",
          "type": "cgroup",
          "source": "cgroup",
          "options": [
            "nosuid",
            "noexec",
            "nodev",
            "relatime",
            "rw"
          ]
        },
        {
          "destination": "/dev/termination-log",
          "type": "bind",
          "source": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/containers/bpfman-agent/26cf34d0",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/etc/crictl.yaml",
          "type": "bind",
          "source": "/etc/crictl.yaml",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/etc/hosts",
          "type": "bind",
          "source": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/etc-hosts",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/etc/hostname",
          "type": "bind",
          "source": "/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99/hostname",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/etc/resolv.conf",
          "type": "bind",
          "source": "/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99/resolv.conf",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/dev/shm",
          "type": "bind",
          "source": "/run/containerd/io.containerd.grpc.v1.cri/sandboxes/ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99/shm",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/etc/bpfman/bpfman.toml",
          "type": "bind",
          "source": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volume-subpaths/bpfman-config/bpfman-agent/1",
          "options": [
            "rbind",
            "rprivate",
            "ro"
          ]
        },
        {
          "destination": "/run/containerd/containerd.sock",
          "type": "bind",
          "source": "/run/containerd/containerd.sock",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/run/crio/crio.sock",
          "type": "bind",
          "source": "/run/crio/crio.sock",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/var/run/dockershim.sock",
          "type": "bind",
          "source": "/var/run/dockershim.sock",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/var/run/cri-dockerd.sock",
          "type": "bind",
          "source": "/var/run/cri-dockerd.sock",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/run/bpfman/sock",
          "type": "bind",
          "source": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volumes/kubernetes.io~empty-dir/bpfman-sock",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/var/run/secrets/kubernetes.io/serviceaccount",
          "type": "bind",
          "source": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volumes/kubernetes.io~projected/kube-api-access-tmkmd",
          "options": [
            "rbind",
            "rprivate",
            "ro"
          ]
        }
      ],
      "hooks": {
        "createContainer": [
          {
            "path": "/kind/bin/mount-product-files.sh"
          }
        ]
      },
      "annotations": {
        "io.kubernetes.cri.container-name": "bpfman-agent",
        "io.kubernetes.cri.container-type": "container",
        "io.kubernetes.cri.image-name": "quay.io/bpfman/bpfman-agent:latest",
        "io.kubernetes.cri.sandbox-id": "ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99",
        "io.kubernetes.cri.sandbox-name": "bpfman-daemon-hf5gv",
        "io.kubernetes.cri.sandbox-namespace": "bpfman",
        "io.kubernetes.cri.sandbox-uid": "88c00a72-09fa-4f0b-b2e7-185fcaff3b0d"
      },
      "linux": {
        "resources": {
          "devices": [
            {
              "allow": true,
              "access": "rwm"
            }
          ],
          "memory": {},
          "cpu": {
            "shares": 2,
            "period": 100000
          }
        },
        "cgroupsPath": "kubelet-kubepods-besteffort-pod88c00a72_09fa_4f0b_b2e7_185fcaff3b0d.slice:cri-containerd:c1ed727676f3ac5c652b706e4576d1ff7680dfb3fd2dc60cfd9cc87cca6d7e01",
        "namespaces": [
          {
            "type": "pid"
          },
          {
            "type": "ipc",
            "path": "/proc/2176/ns/ipc"
          },
          {
            "type": "uts",
            "path": "/proc/2176/ns/uts"
          },
          {
            "type": "mount"
          },
          {
            "type": "network",
            "path": "/proc/2176/ns/net"
          }
        ],
        "devices": [
          {
            "path": "/dev/autofs",
            "type": "c",
            "major": 10,
            "minor": 235,
            "fileMode": 420,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/bsg/10:0:0:0",
            "type": "c",
            "major": 245,
            "minor": 1,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/bsg/11:2:0:0",
            "type": "c",
            "major": 245,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/btrfs-control",
            "type": "c",
            "major": 10,
            "minor": 234,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          },
          {
            "path": "/dev/bus/usb/001/001",
            "type": "c",
            "major": 189,
            "minor": 0,
            "fileMode": 436,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/bus/usb/001/002",
            "type": "c",
            "major": 189,
            "minor": 1,
            "fileMode": 436,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/bus/usb/001/003",
            "type": "c",
            "major": 189,
            "minor": 2,
            "fileMode": 436,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/bus/usb/001/004",
            "type": "c",
            "major": 189,
            "minor": 3,
            "fileMode": 436,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/bus/usb/002/001",
            "type": "c",
            "major": 189,
            "minor": 128,
            "fileMode": 436,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/bus/usb/002/002",
            "type": "c",
            "major": 189,
            "minor": 129,
            "fileMode": 436,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/0/cpuid",
            "type": "c",
            "major": 203,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/0/msr",
            "type": "c",
            "major": 202,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/1/cpuid",
            "type": "c",
            "major": 203,
            "minor": 1,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/1/msr",
            "type": "c",
            "major": 202,
            "minor": 1,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/10/cpuid",
            "type": "c",
            "major": 203,
            "minor": 10,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/10/msr",
            "type": "c",
            "major": 202,
            "minor": 10,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/11/cpuid",
            "type": "c",
            "major": 203,
            "minor": 11,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/11/msr",
            "type": "c",
            "major": 202,
            "minor": 11,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/12/cpuid",
            "type": "c",
            "major": 203,
            "minor": 12,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/12/msr",
            "type": "c",
            "major": 202,
            "minor": 12,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/13/cpuid",
            "type": "c",
            "major": 203,
            "minor": 13,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/13/msr",
            "type": "c",
            "major": 202,
            "minor": 13,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/14/cpuid",
            "type": "c",
            "major": 203,
            "minor": 14,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/14/msr",
            "type": "c",
            "major": 202,
            "minor": 14,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/15/cpuid",
            "type": "c",
            "major": 203,
            "minor": 15,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/15/msr",
            "type": "c",
            "major": 202,
            "minor": 15,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/16/cpuid",
            "type": "c",
            "major": 203,
            "minor": 16,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/16/msr",
            "type": "c",
            "major": 202,
            "minor": 16,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/17/cpuid",
            "type": "c",
            "major": 203,
            "minor": 17,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/17/msr",
            "type": "c",
            "major": 202,
            "minor": 17,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/18/cpuid",
            "type": "c",
            "major": 203,
            "minor": 18,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/18/msr",
            "type": "c",
            "major": 202,
            "minor": 18,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/19/cpuid",
            "type": "c",
            "major": 203,
            "minor": 19,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/19/msr",
            "type": "c",
            "major": 202,
            "minor": 19,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/2/cpuid",
            "type": "c",
            "major": 203,
            "minor": 2,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/2/msr",
            "type": "c",
            "major": 202,
            "minor": 2,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/20/cpuid",
            "type": "c",
            "major": 203,
            "minor": 20,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/20/msr",
            "type": "c",
            "major": 202,
            "minor": 20,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/21/cpuid",
            "type": "c",
            "major": 203,
            "minor": 21,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/21/msr",
            "type": "c",
            "major": 202,
            "minor": 21,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/22/cpuid",
            "type": "c",
            "major": 203,
            "minor": 22,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/22/msr",
            "type": "c",
            "major": 202,
            "minor": 22,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/23/cpuid",
            "type": "c",
            "major": 203,
            "minor": 23,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/23/msr",
            "type": "c",
            "major": 202,
            "minor": 23,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/3/cpuid",
            "type": "c",
            "major": 203,
            "minor": 3,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/3/msr",
            "type": "c",
            "major": 202,
            "minor": 3,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/4/cpuid",
            "type": "c",
            "major": 203,
            "minor": 4,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/4/msr",
            "type": "c",
            "major": 202,
            "minor": 4,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/5/cpuid",
            "type": "c",
            "major": 203,
            "minor": 5,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/5/msr",
            "type": "c",
            "major": 202,
            "minor": 5,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/6/cpuid",
            "type": "c",
            "major": 203,
            "minor": 6,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/6/msr",
            "type": "c",
            "major": 202,
            "minor": 6,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/7/cpuid",
            "type": "c",
            "major": 203,
            "minor": 7,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/7/msr",
            "type": "c",
            "major": 202,
            "minor": 7,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/8/cpuid",
            "type": "c",
            "major": 203,
            "minor": 8,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/8/msr",
            "type": "c",
            "major": 202,
            "minor": 8,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/9/cpuid",
            "type": "c",
            "major": 203,
            "minor": 9,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/9/msr",
            "type": "c",
            "major": 202,
            "minor": 9,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu_dma_latency",
            "type": "c",
            "major": 10,
            "minor": 124,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/dm-0",
            "type": "b",
            "major": 253,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          },
          {
            "path": "/dev/dma_heap/system",
            "type": "c",
            "major": 251,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/dri/card0",
            "type": "c",
            "major": 226,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 39
          },
          {
            "path": "/dev/fb0",
            "type": "c",
            "major": 29,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 39
          },
          {
            "path": "/dev/full",
            "type": "c",
            "major": 1,
            "minor": 7,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/fuse",
            "type": "c",
            "major": 10,
            "minor": 229,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/hpet",
            "type": "c",
            "major": 10,
            "minor": 228,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/hwrng",
            "type": "c",
            "major": 10,
            "minor": 183,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/input/event0",
            "type": "c",
            "major": 13,
            "minor": 64,
            "fileMode": 432,
            "uid": 0,
            "gid": 999
          },
          {
            "path": "/dev/input/mice",
            "type": "c",
            "major": 13,
            "minor": 63,
            "fileMode": 432,
            "uid": 0,
            "gid": 999
          },
          {
            "path": "/dev/ipmi0",
            "type": "c",
            "major": 237,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/kmsg",
            "type": "c",
            "major": 1,
            "minor": 11,
            "fileMode": 420,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/kvm",
            "type": "c",
            "major": 10,
            "minor": 232,
            "fileMode": 432,
            "uid": 0,
            "gid": 102
          },
          {
            "path": "/dev/loop-control",
            "type": "c",
            "major": 10,
            "minor": 237,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          },
          {
            "path": "/dev/mapper/control",
            "type": "c",
            "major": 10,
            "minor": 236,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/mcelog",
            "type": "c",
            "major": 10,
            "minor": 227,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/megaraid_sas_ioctl_node",
            "type": "c",
            "major": 239,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/mem",
            "type": "c",
            "major": 1,
            "minor": 1,
            "fileMode": 416,
            "uid": 0,
            "gid": 9
          },
          {
            "path": "/dev/net/tun",
            "type": "c",
            "major": 10,
            "minor": 200,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/null",
            "type": "c",
            "major": 1,
            "minor": 3,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/nvram",
            "type": "c",
            "major": 10,
            "minor": 144,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/port",
            "type": "c",
            "major": 1,
            "minor": 4,
            "fileMode": 416,
            "uid": 0,
            "gid": 9
          },
          {
            "path": "/dev/ppp",
            "type": "c",
            "major": 108,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/ptp0",
            "type": "c",
            "major": 247,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/ptp1",
            "type": "c",
            "major": 247,
            "minor": 1,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/ptp2",
            "type": "c",
            "major": 247,
            "minor": 2,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/ptp3",
            "type": "c",
            "major": 247,
            "minor": 3,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/random",
            "type": "c",
            "major": 1,
            "minor": 8,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/rfkill",
            "type": "c",
            "major": 10,
            "minor": 242,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/rtc0",
            "type": "c",
            "major": 250,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/sda",
            "type": "b",
            "major": 8,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          },
          {
            "path": "/dev/sda1",
            "type": "b",
            "major": 8,
            "minor": 1,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          },
          {
            "path": "/dev/sda2",
            "type": "b",
            "major": 8,
            "minor": 2,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          },
          {
            "path": "/dev/sg0",
            "type": "c",
            "major": 21,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          },
          {
            "path": "/dev/sg1",
            "type": "c",
            "major": 21,
            "minor": 1,
            "fileMode": 432,
            "uid": 0,
            "gid": 11
          },
          {
            "path": "/dev/snapshot",
            "type": "c",
            "major": 10,
            "minor": 231,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/snd/seq",
            "type": "c",
            "major": 116,
            "minor": 1,
            "fileMode": 432,
            "uid": 0,
            "gid": 29
          },
          {
            "path": "/dev/snd/timer",
            "type": "c",
            "major": 116,
            "minor": 33,
            "fileMode": 432,
            "uid": 0,
            "gid": 29
          },
          {
            "path": "/dev/sr0",
            "type": "b",
            "major": 11,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 11
          },
          {
            "path": "/dev/tpm0",
            "type": "c",
            "major": 10,
            "minor": 224,
            "fileMode": 432,
            "uid": 59,
            "gid": 0
          },
          {
            "path": "/dev/tpmrm0",
            "type": "c",
            "major": 253,
            "minor": 65536,
            "fileMode": 432,
            "uid": 59,
            "gid": 59
          },
          {
            "path": "/dev/tty",
            "type": "c",
            "major": 5,
            "minor": 0,
            "fileMode": 438,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty0",
            "type": "c",
            "major": 4,
            "minor": 0,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty1",
            "type": "c",
            "major": 4,
            "minor": 1,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty10",
            "type": "c",
            "major": 4,
            "minor": 10,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty11",
            "type": "c",
            "major": 4,
            "minor": 11,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty12",
            "type": "c",
            "major": 4,
            "minor": 12,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty13",
            "type": "c",
            "major": 4,
            "minor": 13,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty14",
            "type": "c",
            "major": 4,
            "minor": 14,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty15",
            "type": "c",
            "major": 4,
            "minor": 15,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty16",
            "type": "c",
            "major": 4,
            "minor": 16,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty17",
            "type": "c",
            "major": 4,
            "minor": 17,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty18",
            "type": "c",
            "major": 4,
            "minor": 18,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty19",
            "type": "c",
            "major": 4,
            "minor": 19,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty2",
            "type": "c",
            "major": 4,
            "minor": 2,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty20",
            "type": "c",
            "major": 4,
            "minor": 20,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty21",
            "type": "c",
            "major": 4,
            "minor": 21,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty22",
            "type": "c",
            "major": 4,
            "minor": 22,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty23",
            "type": "c",
            "major": 4,
            "minor": 23,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty24",
            "type": "c",
            "major": 4,
            "minor": 24,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty25",
            "type": "c",
            "major": 4,
            "minor": 25,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty26",
            "type": "c",
            "major": 4,
            "minor": 26,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty27",
            "type": "c",
            "major": 4,
            "minor": 27,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty28",
            "type": "c",
            "major": 4,
            "minor": 28,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty29",
            "type": "c",
            "major": 4,
            "minor": 29,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty3",
            "type": "c",
            "major": 4,
            "minor": 3,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty30",
            "type": "c",
            "major": 4,
            "minor": 30,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty31",
            "type": "c",
            "major": 4,
            "minor": 31,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty32",
            "type": "c",
            "major": 4,
            "minor": 32,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty33",
            "type": "c",
            "major": 4,
            "minor": 33,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty34",
            "type": "c",
            "major": 4,
            "minor": 34,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty35",
            "type": "c",
            "major": 4,
            "minor": 35,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty36",
            "type": "c",
            "major": 4,
            "minor": 36,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty37",
            "type": "c",
            "major": 4,
            "minor": 37,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty38",
            "type": "c",
            "major": 4,
            "minor": 38,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty39",
            "type": "c",
            "major": 4,
            "minor": 39,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty4",
            "type": "c",
            "major": 4,
            "minor": 4,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty40",
            "type": "c",
            "major": 4,
            "minor": 40,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty41",
            "type": "c",
            "major": 4,
            "minor": 41,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty42",
            "type": "c",
            "major": 4,
            "minor": 42,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty43",
            "type": "c",
            "major": 4,
            "minor": 43,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty44",
            "type": "c",
            "major": 4,
            "minor": 44,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty45",
            "type": "c",
            "major": 4,
            "minor": 45,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty46",
            "type": "c",
            "major": 4,
            "minor": 46,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty47",
            "type": "c",
            "major": 4,
            "minor": 47,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty48",
            "type": "c",
            "major": 4,
            "minor": 48,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty49",
            "type": "c",
            "major": 4,
            "minor": 49,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty5",
            "type": "c",
            "major": 4,
            "minor": 5,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty50",
            "type": "c",
            "major": 4,
            "minor": 50,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty51",
            "type": "c",
            "major": 4,
            "minor": 51,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty52",
            "type": "c",
            "major": 4,
            "minor": 52,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty53",
            "type": "c",
            "major": 4,
            "minor": 53,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty54",
            "type": "c",
            "major": 4,
            "minor": 54,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty55",
            "type": "c",
            "major": 4,
            "minor": 55,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty56",
            "type": "c",
            "major": 4,
            "minor": 56,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty57",
            "type": "c",
            "major": 4,
            "minor": 57,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty58",
            "type": "c",
            "major": 4,
            "minor": 58,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty59",
            "type": "c",
            "major": 4,
            "minor": 59,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty6",
            "type": "c",
            "major": 4,
            "minor": 6,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty60",
            "type": "c",
            "major": 4,
            "minor": 60,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty61",
            "type": "c",
            "major": 4,
            "minor": 61,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty62",
            "type": "c",
            "major": 4,
            "minor": 62,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty63",
            "type": "c",
            "major": 4,
            "minor": 63,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty7",
            "type": "c",
            "major": 4,
            "minor": 7,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty8",
            "type": "c",
            "major": 4,
            "minor": 8,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty9",
            "type": "c",
            "major": 4,
            "minor": 9,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/ttyS0",
            "type": "c",
            "major": 4,
            "minor": 64,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS1",
            "type": "c",
            "major": 4,
            "minor": 65,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS10",
            "type": "c",
            "major": 4,
            "minor": 74,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS11",
            "type": "c",
            "major": 4,
            "minor": 75,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS12",
            "type": "c",
            "major": 4,
            "minor": 76,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS13",
            "type": "c",
            "major": 4,
            "minor": 77,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS14",
            "type": "c",
            "major": 4,
            "minor": 78,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS15",
            "type": "c",
            "major": 4,
            "minor": 79,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS16",
            "type": "c",
            "major": 4,
            "minor": 80,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS17",
            "type": "c",
            "major": 4,
            "minor": 81,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS18",
            "type": "c",
            "major": 4,
            "minor": 82,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS19",
            "type": "c",
            "major": 4,
            "minor": 83,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS2",
            "type": "c",
            "major": 4,
            "minor": 66,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS20",
            "type": "c",
            "major": 4,
            "minor": 84,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS21",
            "type": "c",
            "major": 4,
            "minor": 85,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS22",
            "type": "c",
            "major": 4,
            "minor": 86,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS23",
            "type": "c",
            "major": 4,
            "minor": 87,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS24",
            "type": "c",
            "major": 4,
            "minor": 88,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS25",
            "type": "c",
            "major": 4,
            "minor": 89,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS26",
            "type": "c",
            "major": 4,
            "minor": 90,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS27",
            "type": "c",
            "major": 4,
            "minor": 91,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS28",
            "type": "c",
            "major": 4,
            "minor": 92,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS29",
            "type": "c",
            "major": 4,
            "minor": 93,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS3",
            "type": "c",
            "major": 4,
            "minor": 67,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS30",
            "type": "c",
            "major": 4,
            "minor": 94,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS31",
            "type": "c",
            "major": 4,
            "minor": 95,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS4",
            "type": "c",
            "major": 4,
            "minor": 68,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS5",
            "type": "c",
            "major": 4,
            "minor": 69,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS6",
            "type": "c",
            "major": 4,
            "minor": 70,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS7",
            "type": "c",
            "major": 4,
            "minor": 71,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS8",
            "type": "c",
            "major": 4,
            "minor": 72,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS9",
            "type": "c",
            "major": 4,
            "minor": 73,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/udmabuf",
            "type": "c",
            "major": 10,
            "minor": 125,
            "fileMode": 432,
            "uid": 0,
            "gid": 36
          },
          {
            "path": "/dev/uhid",
            "type": "c",
            "major": 10,
            "minor": 239,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/uinput",
            "type": "c",
            "major": 10,
            "minor": 223,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/urandom",
            "type": "c",
            "major": 1,
            "minor": 9,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/usbmon0",
            "type": "c",
            "major": 243,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/usbmon1",
            "type": "c",
            "major": 243,
            "minor": 1,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/usbmon2",
            "type": "c",
            "major": 243,
            "minor": 2,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/userfaultfd",
            "type": "c",
            "major": 10,
            "minor": 126,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/vcs",
            "type": "c",
            "major": 7,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcs1",
            "type": "c",
            "major": 7,
            "minor": 1,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcs2",
            "type": "c",
            "major": 7,
            "minor": 2,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcs3",
            "type": "c",
            "major": 7,
            "minor": 3,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcs4",
            "type": "c",
            "major": 7,
            "minor": 4,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcs5",
            "type": "c",
            "major": 7,
            "minor": 5,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcs6",
            "type": "c",
            "major": 7,
            "minor": 6,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsa",
            "type": "c",
            "major": 7,
            "minor": 128,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsa1",
            "type": "c",
            "major": 7,
            "minor": 129,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsa2",
            "type": "c",
            "major": 7,
            "minor": 130,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsa3",
            "type": "c",
            "major": 7,
            "minor": 131,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsa4",
            "type": "c",
            "major": 7,
            "minor": 132,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsa5",
            "type": "c",
            "major": 7,
            "minor": 133,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsa6",
            "type": "c",
            "major": 7,
            "minor": 134,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsu",
            "type": "c",
            "major": 7,
            "minor": 64,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsu1",
            "type": "c",
            "major": 7,
            "minor": 65,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsu2",
            "type": "c",
            "major": 7,
            "minor": 66,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsu3",
            "type": "c",
            "major": 7,
            "minor": 67,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsu4",
            "type": "c",
            "major": 7,
            "minor": 68,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsu5",
            "type": "c",
            "major": 7,
            "minor": 69,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsu6",
            "type": "c",
            "major": 7,
            "minor": 70,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vfio/vfio",
            "type": "c",
            "major": 10,
            "minor": 196,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/vga_arbiter",
            "type": "c",
            "major": 10,
            "minor": 127,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/vhci",
            "type": "c",
            "major": 10,
            "minor": 137,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/vhost-net",
            "type": "c",
            "major": 10,
            "minor": 238,
            "fileMode": 384,
            "uid": 0,
            "gid": 36
          },
          {
            "path": "/dev/vhost-vsock",
            "type": "c",
            "major": 10,
            "minor": 241,
            "fileMode": 384,
            "uid": 0,
            "gid": 36
          },
          {
            "path": "/dev/watchdog",
            "type": "c",
            "major": 10,
            "minor": 130,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/watchdog0",
            "type": "c",
            "major": 246,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/zero",
            "type": "c",
            "major": 1,
            "minor": 5,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/zram0",
            "type": "b",
            "major": 252,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          }
        ]
      }
    }
  }
}`)

	containerData2 := []byte(`{
  "status": {
    "id": "ee31cab3b7ff9aa60fc4d686fec84881f79fb4194ccf4eb7dda793db04ad48db",
    "metadata": {
      "attempt": 0,
      "name": "bpfman"
    },
    "state": "CONTAINER_RUNNING",
    "createdAt": "2024-01-04T18:09:59.242101914Z",
    "startedAt": "2024-01-04T18:09:59.410772004Z",
    "finishedAt": "0001-01-01T00:00:00Z",
    "exitCode": 0,
    "image": {
      "annotations": {},
      "image": "quay.io/bpfman/bpfman:latest",
      "userSpecifiedImage": ""
    },
    "imageRef": "docker.io/library/import-2024-01-04@sha256:2f1ef2b4af7eaaa7c5e8f844d394f6005ed83fe78ba2922b3539534f1da9c8f3",
    "reason": "",
    "message": "",
    "labels": {
      "io.kubernetes.container.name": "bpfman",
      "io.kubernetes.pod.name": "bpfman-daemon-hf5gv",
      "io.kubernetes.pod.namespace": "bpfman",
      "io.kubernetes.pod.uid": "88c00a72-09fa-4f0b-b2e7-185fcaff3b0d"
    },
    "annotations": {
      "io.kubernetes.container.hash": "5bc1a944",
      "io.kubernetes.container.restartCount": "0",
      "io.kubernetes.container.terminationMessagePath": "/dev/termination-log",
      "io.kubernetes.container.terminationMessagePolicy": "File",
      "io.kubernetes.pod.terminationGracePeriod": "15"
    },
    "mounts": [
      {
        "containerPath": "/run/bpfman/sock",
        "gidMappings": [],
        "hostPath": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volumes/kubernetes.io~empty-dir/bpfman-sock",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/run/bpfman",
        "gidMappings": [],
        "hostPath": "/run/bpfman",
        "propagation": "PROPAGATION_BIDIRECTIONAL",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/sys/kernel/debug",
        "gidMappings": [],
        "hostPath": "/sys/kernel/debug",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/var/lib/bpfman",
        "gidMappings": [],
        "hostPath": "/var/lib/bpfman",
        "propagation": "PROPAGATION_BIDIRECTIONAL",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/sys/fs/bpf",
        "gidMappings": [],
        "hostPath": "/sys/fs/bpf",
        "propagation": "PROPAGATION_BIDIRECTIONAL",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/run/bpfman/csi",
        "gidMappings": [],
        "hostPath": "/var/lib/kubelet/plugins/csi-bpfman",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/var/lib/kubelet/pods",
        "gidMappings": [],
        "hostPath": "/var/lib/kubelet/pods",
        "propagation": "PROPAGATION_BIDIRECTIONAL",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/tmp",
        "gidMappings": [],
        "hostPath": "/tmp",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/host/proc",
        "gidMappings": [],
        "hostPath": "/proc",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/var/run/secrets/kubernetes.io/serviceaccount",
        "gidMappings": [],
        "hostPath": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volumes/kubernetes.io~projected/kube-api-access-tmkmd",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": true,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/etc/hosts",
        "gidMappings": [],
        "hostPath": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/etc-hosts",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/dev/termination-log",
        "gidMappings": [],
        "hostPath": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/containers/bpfman/b8160460",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      }
    ],
    "logPath": "/var/log/pods/bpfman_bpfman-daemon-hf5gv_88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/bpfman/0.log",
    "resources": {
      "linux": {
        "cpuPeriod": "100000",
        "cpuQuota": "0",
        "cpuShares": "2",
        "cpusetCpus": "",
        "cpusetMems": "",
        "hugepageLimits": [],
        "memoryLimitInBytes": "0",
        "memorySwapLimitInBytes": "0",
        "oomScoreAdj": "1000",
        "unified": {}
      },
      "windows": null
    }
  },
  "info": {
    "sandboxID": "ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99",
    "pid": 2285,
    "removing": false,
    "snapshotKey": "ee31cab3b7ff9aa60fc4d686fec84881f79fb4194ccf4eb7dda793db04ad48db",
    "snapshotter": "overlayfs",
    "runtimeType": "io.containerd.runc.v2",
    "runtimeOptions": {
      "systemd_cgroup": true
    },
    "config": {
      "metadata": {
        "name": "bpfman"
      },
      "image": {
        "image": "sha256:4f296bdff30513d83c41007bdb1c0f07fc443382f97d074131e1e7c3c46d257b"
      },
      "args": [
        "--csi-support"
      ],
      "envs": [
        {
          "key": "RUST_LOG",
          "value": "debug"
        },
        {
          "key": "KUBE_NODE_NAME",
          "value": "bpfman-deployment-control-plane"
        },
        {
          "key": "KUBERNETES_SERVICE_PORT",
          "value": "443"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_HOST",
          "value": "10.96.207.4"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_PORT_HTTPS",
          "value": "8443"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP",
          "value": "tcp://10.96.207.4:8443"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_PORT",
          "value": "8443"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_ADDR",
          "value": "10.96.207.4"
        },
        {
          "key": "KUBERNETES_SERVICE_HOST",
          "value": "10.96.0.1"
        },
        {
          "key": "KUBERNETES_PORT_443_TCP",
          "value": "tcp://10.96.0.1:443"
        },
        {
          "key": "KUBERNETES_PORT_443_TCP_PORT",
          "value": "443"
        },
        {
          "key": "KUBERNETES_PORT_443_TCP_ADDR",
          "value": "10.96.0.1"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT",
          "value": "tcp://10.96.207.4:8443"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_PROTO",
          "value": "tcp"
        },
        {
          "key": "KUBERNETES_PORT",
          "value": "tcp://10.96.0.1:443"
        },
        {
          "key": "KUBERNETES_SERVICE_PORT_HTTPS",
          "value": "443"
        },
        {
          "key": "KUBERNETES_PORT_443_TCP_PROTO",
          "value": "tcp"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_PORT",
          "value": "8443"
        }
      ],
      "mounts": [
        {
          "container_path": "/run/bpfman/sock",
          "host_path": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volumes/kubernetes.io~empty-dir/bpfman-sock"
        },
        {
          "container_path": "/run/bpfman",
          "host_path": "/run/bpfman",
          "propagation": 2
        },
        {
          "container_path": "/sys/kernel/debug",
          "host_path": "/sys/kernel/debug"
        },
        {
          "container_path": "/var/lib/bpfman",
          "host_path": "/var/lib/bpfman",
          "propagation": 2
        },
        {
          "container_path": "/sys/fs/bpf",
          "host_path": "/sys/fs/bpf",
          "propagation": 2
        },
        {
          "container_path": "/run/bpfman/csi",
          "host_path": "/var/lib/kubelet/plugins/csi-bpfman"
        },
        {
          "container_path": "/var/lib/kubelet/pods",
          "host_path": "/var/lib/kubelet/pods",
          "propagation": 2
        },
        {
          "container_path": "/tmp",
          "host_path": "/tmp"
        },
        {
          "container_path": "/host/proc",
          "host_path": "/proc"
        },
        {
          "container_path": "/var/run/secrets/kubernetes.io/serviceaccount",
          "host_path": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volumes/kubernetes.io~projected/kube-api-access-tmkmd",
          "readonly": true
        },
        {
          "container_path": "/etc/hosts",
          "host_path": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/etc-hosts"
        },
        {
          "container_path": "/dev/termination-log",
          "host_path": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/containers/bpfman/b8160460"
        }
      ],
      "labels": {
        "io.kubernetes.container.name": "bpfman",
        "io.kubernetes.pod.name": "bpfman-daemon-hf5gv",
        "io.kubernetes.pod.namespace": "bpfman",
        "io.kubernetes.pod.uid": "88c00a72-09fa-4f0b-b2e7-185fcaff3b0d"
      },
      "annotations": {
        "io.kubernetes.container.hash": "5bc1a944",
        "io.kubernetes.container.restartCount": "0",
        "io.kubernetes.container.terminationMessagePath": "/dev/termination-log",
        "io.kubernetes.container.terminationMessagePolicy": "File",
        "io.kubernetes.pod.terminationGracePeriod": "15"
      },
      "log_path": "bpfman/0.log",
      "linux": {
        "resources": {
          "cpu_period": 100000,
          "cpu_shares": 2,
          "oom_score_adj": 1000,
          "hugepage_limits": [
            {
              "page_size": "2MB"
            },
            {
              "page_size": "1GB"
            }
          ]
        },
        "security_context": {
          "privileged": true,
          "namespace_options": {
            "network": 2,
            "pid": 1
          },
          "run_as_user": {},
          "supplemental_groups": [
            2000
          ],
          "masked_paths": [
            "/proc/asound",
            "/proc/acpi",
            "/proc/kcore",
            "/proc/keys",
            "/proc/latency_stats",
            "/proc/timer_list",
            "/proc/timer_stats",
            "/proc/sched_debug",
            "/proc/scsi",
            "/sys/firmware"
          ],
          "readonly_paths": [
            "/proc/bus",
            "/proc/fs",
            "/proc/irq",
            "/proc/sys",
            "/proc/sysrq-trigger"
          ],
          "seccomp": {
            "profile_type": 1
          }
        }
      }
    },
    "runtimeSpec": {
      "ociVersion": "1.1.0-rc.1",
      "process": {
        "user": {
          "uid": 0,
          "gid": 0,
          "additionalGids": [
            0,
            2000
          ]
        },
        "args": [
          "./bpfman",
          "system",
          "service",
          "--csi-support"
        ],
        "env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "HOSTNAME=bpfman-deployment-control-plane",
          "DISTTAG=f38container",
          "FGC=f38",
          "FBR=f38",
          "RUST_LOG=debug",
          "KUBE_NODE_NAME=bpfman-deployment-control-plane",
          "KUBERNETES_SERVICE_PORT=443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_HOST=10.96.207.4",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_PORT_HTTPS=8443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP=tcp://10.96.207.4:8443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_PORT=8443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_ADDR=10.96.207.4",
          "KUBERNETES_SERVICE_HOST=10.96.0.1",
          "KUBERNETES_PORT_443_TCP=tcp://10.96.0.1:443",
          "KUBERNETES_PORT_443_TCP_PORT=443",
          "KUBERNETES_PORT_443_TCP_ADDR=10.96.0.1",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT=tcp://10.96.207.4:8443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_PROTO=tcp",
          "KUBERNETES_PORT=tcp://10.96.0.1:443",
          "KUBERNETES_SERVICE_PORT_HTTPS=443",
          "KUBERNETES_PORT_443_TCP_PROTO=tcp",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_PORT=8443"
        ],
        "cwd": "/",
        "capabilities": {
          "bounding": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
            "CAP_PERFMON",
            "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE"
          ],
          "effective": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
            "CAP_PERFMON",
            "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE"
          ],
          "permitted": [
            "CAP_CHOWN",
            "CAP_DAC_OVERRIDE",
            "CAP_DAC_READ_SEARCH",
            "CAP_FOWNER",
            "CAP_FSETID",
            "CAP_KILL",
            "CAP_SETGID",
            "CAP_SETUID",
            "CAP_SETPCAP",
            "CAP_LINUX_IMMUTABLE",
            "CAP_NET_BIND_SERVICE",
            "CAP_NET_BROADCAST",
            "CAP_NET_ADMIN",
            "CAP_NET_RAW",
            "CAP_IPC_LOCK",
            "CAP_IPC_OWNER",
            "CAP_SYS_MODULE",
            "CAP_SYS_RAWIO",
            "CAP_SYS_CHROOT",
            "CAP_SYS_PTRACE",
            "CAP_SYS_PACCT",
            "CAP_SYS_ADMIN",
            "CAP_SYS_BOOT",
            "CAP_SYS_NICE",
            "CAP_SYS_RESOURCE",
            "CAP_SYS_TIME",
            "CAP_SYS_TTY_CONFIG",
            "CAP_MKNOD",
            "CAP_LEASE",
            "CAP_AUDIT_WRITE",
            "CAP_AUDIT_CONTROL",
            "CAP_SETFCAP",
            "CAP_MAC_OVERRIDE",
            "CAP_MAC_ADMIN",
            "CAP_SYSLOG",
            "CAP_WAKE_ALARM",
            "CAP_BLOCK_SUSPEND",
            "CAP_AUDIT_READ",
            "CAP_PERFMON",
            "CAP_BPF",
            "CAP_CHECKPOINT_RESTORE"
          ]
        },
        "oomScoreAdj": 1000
      },
      "root": {
        "path": "rootfs"
      },
      "mounts": [
        {
          "destination": "/proc",
          "type": "proc",
          "source": "proc",
          "options": [
            "nosuid",
            "noexec",
            "nodev"
          ]
        },
        {
          "destination": "/dev",
          "type": "tmpfs",
          "source": "tmpfs",
          "options": [
            "nosuid",
            "strictatime",
            "mode=755",
            "size=65536k"
          ]
        },
        {
          "destination": "/dev/pts",
          "type": "devpts",
          "source": "devpts",
          "options": [
            "nosuid",
            "noexec",
            "newinstance",
            "ptmxmode=0666",
            "mode=0620",
            "gid=5"
          ]
        },
        {
          "destination": "/dev/mqueue",
          "type": "mqueue",
          "source": "mqueue",
          "options": [
            "nosuid",
            "noexec",
            "nodev"
          ]
        },
        {
          "destination": "/sys",
          "type": "sysfs",
          "source": "sysfs",
          "options": [
            "nosuid",
            "noexec",
            "nodev",
            "rw"
          ]
        },
        {
          "destination": "/sys/fs/cgroup",
          "type": "cgroup",
          "source": "cgroup",
          "options": [
            "nosuid",
            "noexec",
            "nodev",
            "relatime",
            "rw"
          ]
        },
        {
          "destination": "/tmp",
          "type": "bind",
          "source": "/tmp",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/host/proc",
          "type": "bind",
          "source": "/proc",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/run/bpfman",
          "type": "bind",
          "source": "/run/bpfman",
          "options": [
            "rbind",
            "rshared",
            "rw"
          ]
        },
        {
          "destination": "/etc/hostname",
          "type": "bind",
          "source": "/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99/hostname",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/etc/resolv.conf",
          "type": "bind",
          "source": "/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99/resolv.conf",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/dev/termination-log",
          "type": "bind",
          "source": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/containers/bpfman/b8160460",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/etc/hosts",
          "type": "bind",
          "source": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/etc-hosts",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/dev/shm",
          "type": "bind",
          "source": "/run/containerd/io.containerd.grpc.v1.cri/sandboxes/ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99/shm",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/var/lib/bpfman",
          "type": "bind",
          "source": "/var/lib/bpfman",
          "options": [
            "rbind",
            "rshared",
            "rw"
          ]
        },
        {
          "destination": "/run/bpfman/sock",
          "type": "bind",
          "source": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volumes/kubernetes.io~empty-dir/bpfman-sock",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/run/bpfman/csi",
          "type": "bind",
          "source": "/var/lib/kubelet/plugins/csi-bpfman",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/sys/fs/bpf",
          "type": "bind",
          "source": "/sys/fs/bpf",
          "options": [
            "rbind",
            "rshared",
            "rw"
          ]
        },
        {
          "destination": "/sys/kernel/debug",
          "type": "bind",
          "source": "/sys/kernel/debug",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/var/lib/kubelet/pods",
          "type": "bind",
          "source": "/var/lib/kubelet/pods",
          "options": [
            "rbind",
            "rshared",
            "rw"
          ]
        },
        {
          "destination": "/var/run/secrets/kubernetes.io/serviceaccount",
          "type": "bind",
          "source": "/var/lib/kubelet/pods/88c00a72-09fa-4f0b-b2e7-185fcaff3b0d/volumes/kubernetes.io~projected/kube-api-access-tmkmd",
          "options": [
            "rbind",
            "rprivate",
            "ro"
          ]
        }
      ],
      "hooks": {
        "createContainer": [
          {
            "path": "/kind/bin/mount-product-files.sh"
          }
        ]
      },
      "annotations": {
        "io.kubernetes.cri.container-name": "bpfman",
        "io.kubernetes.cri.container-type": "container",
        "io.kubernetes.cri.image-name": "quay.io/bpfman/bpfman:latest",
        "io.kubernetes.cri.sandbox-id": "ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99",
        "io.kubernetes.cri.sandbox-name": "bpfman-daemon-hf5gv",
        "io.kubernetes.cri.sandbox-namespace": "bpfman",
        "io.kubernetes.cri.sandbox-uid": "88c00a72-09fa-4f0b-b2e7-185fcaff3b0d"
      },
      "linux": {
        "resources": {
          "devices": [
            {
              "allow": true,
              "access": "rwm"
            }
          ],
          "memory": {},
          "cpu": {
            "shares": 2,
            "period": 100000
          }
        },
        "cgroupsPath": "kubelet-kubepods-besteffort-pod88c00a72_09fa_4f0b_b2e7_185fcaff3b0d.slice:cri-containerd:ee31cab3b7ff9aa60fc4d686fec84881f79fb4194ccf4eb7dda793db04ad48db",
        "namespaces": [
          {
            "type": "pid"
          },
          {
            "type": "ipc",
            "path": "/proc/2176/ns/ipc"
          },
          {
            "type": "uts",
            "path": "/proc/2176/ns/uts"
          },
          {
            "type": "mount"
          },
          {
            "type": "network",
            "path": "/proc/2176/ns/net"
          }
        ],
        "devices": [
          {
            "path": "/dev/autofs",
            "type": "c",
            "major": 10,
            "minor": 235,
            "fileMode": 420,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/bsg/10:0:0:0",
            "type": "c",
            "major": 245,
            "minor": 1,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/bsg/11:2:0:0",
            "type": "c",
            "major": 245,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/btrfs-control",
            "type": "c",
            "major": 10,
            "minor": 234,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          },
          {
            "path": "/dev/bus/usb/001/001",
            "type": "c",
            "major": 189,
            "minor": 0,
            "fileMode": 436,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/bus/usb/001/002",
            "type": "c",
            "major": 189,
            "minor": 1,
            "fileMode": 436,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/bus/usb/001/003",
            "type": "c",
            "major": 189,
            "minor": 2,
            "fileMode": 436,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/bus/usb/001/004",
            "type": "c",
            "major": 189,
            "minor": 3,
            "fileMode": 436,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/bus/usb/002/001",
            "type": "c",
            "major": 189,
            "minor": 128,
            "fileMode": 436,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/bus/usb/002/002",
            "type": "c",
            "major": 189,
            "minor": 129,
            "fileMode": 436,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/0/cpuid",
            "type": "c",
            "major": 203,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/0/msr",
            "type": "c",
            "major": 202,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/1/cpuid",
            "type": "c",
            "major": 203,
            "minor": 1,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/1/msr",
            "type": "c",
            "major": 202,
            "minor": 1,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/10/cpuid",
            "type": "c",
            "major": 203,
            "minor": 10,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/10/msr",
            "type": "c",
            "major": 202,
            "minor": 10,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/11/cpuid",
            "type": "c",
            "major": 203,
            "minor": 11,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/11/msr",
            "type": "c",
            "major": 202,
            "minor": 11,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/12/cpuid",
            "type": "c",
            "major": 203,
            "minor": 12,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/12/msr",
            "type": "c",
            "major": 202,
            "minor": 12,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/13/cpuid",
            "type": "c",
            "major": 203,
            "minor": 13,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/13/msr",
            "type": "c",
            "major": 202,
            "minor": 13,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/14/cpuid",
            "type": "c",
            "major": 203,
            "minor": 14,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/14/msr",
            "type": "c",
            "major": 202,
            "minor": 14,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/15/cpuid",
            "type": "c",
            "major": 203,
            "minor": 15,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/15/msr",
            "type": "c",
            "major": 202,
            "minor": 15,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/16/cpuid",
            "type": "c",
            "major": 203,
            "minor": 16,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/16/msr",
            "type": "c",
            "major": 202,
            "minor": 16,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/17/cpuid",
            "type": "c",
            "major": 203,
            "minor": 17,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/17/msr",
            "type": "c",
            "major": 202,
            "minor": 17,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/18/cpuid",
            "type": "c",
            "major": 203,
            "minor": 18,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/18/msr",
            "type": "c",
            "major": 202,
            "minor": 18,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/19/cpuid",
            "type": "c",
            "major": 203,
            "minor": 19,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/19/msr",
            "type": "c",
            "major": 202,
            "minor": 19,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/2/cpuid",
            "type": "c",
            "major": 203,
            "minor": 2,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/2/msr",
            "type": "c",
            "major": 202,
            "minor": 2,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/20/cpuid",
            "type": "c",
            "major": 203,
            "minor": 20,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/20/msr",
            "type": "c",
            "major": 202,
            "minor": 20,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/21/cpuid",
            "type": "c",
            "major": 203,
            "minor": 21,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/21/msr",
            "type": "c",
            "major": 202,
            "minor": 21,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/22/cpuid",
            "type": "c",
            "major": 203,
            "minor": 22,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/22/msr",
            "type": "c",
            "major": 202,
            "minor": 22,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/23/cpuid",
            "type": "c",
            "major": 203,
            "minor": 23,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/23/msr",
            "type": "c",
            "major": 202,
            "minor": 23,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/3/cpuid",
            "type": "c",
            "major": 203,
            "minor": 3,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/3/msr",
            "type": "c",
            "major": 202,
            "minor": 3,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/4/cpuid",
            "type": "c",
            "major": 203,
            "minor": 4,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/4/msr",
            "type": "c",
            "major": 202,
            "minor": 4,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/5/cpuid",
            "type": "c",
            "major": 203,
            "minor": 5,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/5/msr",
            "type": "c",
            "major": 202,
            "minor": 5,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/6/cpuid",
            "type": "c",
            "major": 203,
            "minor": 6,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/6/msr",
            "type": "c",
            "major": 202,
            "minor": 6,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/7/cpuid",
            "type": "c",
            "major": 203,
            "minor": 7,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/7/msr",
            "type": "c",
            "major": 202,
            "minor": 7,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/8/cpuid",
            "type": "c",
            "major": 203,
            "minor": 8,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/8/msr",
            "type": "c",
            "major": 202,
            "minor": 8,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/9/cpuid",
            "type": "c",
            "major": 203,
            "minor": 9,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu/9/msr",
            "type": "c",
            "major": 202,
            "minor": 9,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/cpu_dma_latency",
            "type": "c",
            "major": 10,
            "minor": 124,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/dm-0",
            "type": "b",
            "major": 253,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          },
          {
            "path": "/dev/dma_heap/system",
            "type": "c",
            "major": 251,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/dri/card0",
            "type": "c",
            "major": 226,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 39
          },
          {
            "path": "/dev/fb0",
            "type": "c",
            "major": 29,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 39
          },
          {
            "path": "/dev/full",
            "type": "c",
            "major": 1,
            "minor": 7,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/fuse",
            "type": "c",
            "major": 10,
            "minor": 229,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/hpet",
            "type": "c",
            "major": 10,
            "minor": 228,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/hwrng",
            "type": "c",
            "major": 10,
            "minor": 183,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/input/event0",
            "type": "c",
            "major": 13,
            "minor": 64,
            "fileMode": 432,
            "uid": 0,
            "gid": 999
          },
          {
            "path": "/dev/input/mice",
            "type": "c",
            "major": 13,
            "minor": 63,
            "fileMode": 432,
            "uid": 0,
            "gid": 999
          },
          {
            "path": "/dev/ipmi0",
            "type": "c",
            "major": 237,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/kmsg",
            "type": "c",
            "major": 1,
            "minor": 11,
            "fileMode": 420,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/kvm",
            "type": "c",
            "major": 10,
            "minor": 232,
            "fileMode": 432,
            "uid": 0,
            "gid": 102
          },
          {
            "path": "/dev/loop-control",
            "type": "c",
            "major": 10,
            "minor": 237,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          },
          {
            "path": "/dev/mapper/control",
            "type": "c",
            "major": 10,
            "minor": 236,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/mcelog",
            "type": "c",
            "major": 10,
            "minor": 227,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/megaraid_sas_ioctl_node",
            "type": "c",
            "major": 239,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/mem",
            "type": "c",
            "major": 1,
            "minor": 1,
            "fileMode": 416,
            "uid": 0,
            "gid": 9
          },
          {
            "path": "/dev/net/tun",
            "type": "c",
            "major": 10,
            "minor": 200,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/null",
            "type": "c",
            "major": 1,
            "minor": 3,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/nvram",
            "type": "c",
            "major": 10,
            "minor": 144,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/port",
            "type": "c",
            "major": 1,
            "minor": 4,
            "fileMode": 416,
            "uid": 0,
            "gid": 9
          },
          {
            "path": "/dev/ppp",
            "type": "c",
            "major": 108,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/ptp0",
            "type": "c",
            "major": 247,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/ptp1",
            "type": "c",
            "major": 247,
            "minor": 1,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/ptp2",
            "type": "c",
            "major": 247,
            "minor": 2,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/ptp3",
            "type": "c",
            "major": 247,
            "minor": 3,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/random",
            "type": "c",
            "major": 1,
            "minor": 8,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/rfkill",
            "type": "c",
            "major": 10,
            "minor": 242,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/rtc0",
            "type": "c",
            "major": 250,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/sda",
            "type": "b",
            "major": 8,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          },
          {
            "path": "/dev/sda1",
            "type": "b",
            "major": 8,
            "minor": 1,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          },
          {
            "path": "/dev/sda2",
            "type": "b",
            "major": 8,
            "minor": 2,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          },
          {
            "path": "/dev/sg0",
            "type": "c",
            "major": 21,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          },
          {
            "path": "/dev/sg1",
            "type": "c",
            "major": 21,
            "minor": 1,
            "fileMode": 432,
            "uid": 0,
            "gid": 11
          },
          {
            "path": "/dev/snapshot",
            "type": "c",
            "major": 10,
            "minor": 231,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/snd/seq",
            "type": "c",
            "major": 116,
            "minor": 1,
            "fileMode": 432,
            "uid": 0,
            "gid": 29
          },
          {
            "path": "/dev/snd/timer",
            "type": "c",
            "major": 116,
            "minor": 33,
            "fileMode": 432,
            "uid": 0,
            "gid": 29
          },
          {
            "path": "/dev/sr0",
            "type": "b",
            "major": 11,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 11
          },
          {
            "path": "/dev/tpm0",
            "type": "c",
            "major": 10,
            "minor": 224,
            "fileMode": 432,
            "uid": 59,
            "gid": 0
          },
          {
            "path": "/dev/tpmrm0",
            "type": "c",
            "major": 253,
            "minor": 65536,
            "fileMode": 432,
            "uid": 59,
            "gid": 59
          },
          {
            "path": "/dev/tty",
            "type": "c",
            "major": 5,
            "minor": 0,
            "fileMode": 438,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty0",
            "type": "c",
            "major": 4,
            "minor": 0,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty1",
            "type": "c",
            "major": 4,
            "minor": 1,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty10",
            "type": "c",
            "major": 4,
            "minor": 10,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty11",
            "type": "c",
            "major": 4,
            "minor": 11,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty12",
            "type": "c",
            "major": 4,
            "minor": 12,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty13",
            "type": "c",
            "major": 4,
            "minor": 13,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty14",
            "type": "c",
            "major": 4,
            "minor": 14,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty15",
            "type": "c",
            "major": 4,
            "minor": 15,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty16",
            "type": "c",
            "major": 4,
            "minor": 16,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty17",
            "type": "c",
            "major": 4,
            "minor": 17,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty18",
            "type": "c",
            "major": 4,
            "minor": 18,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty19",
            "type": "c",
            "major": 4,
            "minor": 19,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty2",
            "type": "c",
            "major": 4,
            "minor": 2,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty20",
            "type": "c",
            "major": 4,
            "minor": 20,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty21",
            "type": "c",
            "major": 4,
            "minor": 21,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty22",
            "type": "c",
            "major": 4,
            "minor": 22,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty23",
            "type": "c",
            "major": 4,
            "minor": 23,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty24",
            "type": "c",
            "major": 4,
            "minor": 24,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty25",
            "type": "c",
            "major": 4,
            "minor": 25,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty26",
            "type": "c",
            "major": 4,
            "minor": 26,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty27",
            "type": "c",
            "major": 4,
            "minor": 27,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty28",
            "type": "c",
            "major": 4,
            "minor": 28,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty29",
            "type": "c",
            "major": 4,
            "minor": 29,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty3",
            "type": "c",
            "major": 4,
            "minor": 3,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty30",
            "type": "c",
            "major": 4,
            "minor": 30,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty31",
            "type": "c",
            "major": 4,
            "minor": 31,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty32",
            "type": "c",
            "major": 4,
            "minor": 32,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty33",
            "type": "c",
            "major": 4,
            "minor": 33,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty34",
            "type": "c",
            "major": 4,
            "minor": 34,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty35",
            "type": "c",
            "major": 4,
            "minor": 35,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty36",
            "type": "c",
            "major": 4,
            "minor": 36,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty37",
            "type": "c",
            "major": 4,
            "minor": 37,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty38",
            "type": "c",
            "major": 4,
            "minor": 38,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty39",
            "type": "c",
            "major": 4,
            "minor": 39,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty4",
            "type": "c",
            "major": 4,
            "minor": 4,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty40",
            "type": "c",
            "major": 4,
            "minor": 40,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty41",
            "type": "c",
            "major": 4,
            "minor": 41,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty42",
            "type": "c",
            "major": 4,
            "minor": 42,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty43",
            "type": "c",
            "major": 4,
            "minor": 43,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty44",
            "type": "c",
            "major": 4,
            "minor": 44,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty45",
            "type": "c",
            "major": 4,
            "minor": 45,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty46",
            "type": "c",
            "major": 4,
            "minor": 46,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty47",
            "type": "c",
            "major": 4,
            "minor": 47,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty48",
            "type": "c",
            "major": 4,
            "minor": 48,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty49",
            "type": "c",
            "major": 4,
            "minor": 49,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty5",
            "type": "c",
            "major": 4,
            "minor": 5,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty50",
            "type": "c",
            "major": 4,
            "minor": 50,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty51",
            "type": "c",
            "major": 4,
            "minor": 51,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty52",
            "type": "c",
            "major": 4,
            "minor": 52,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty53",
            "type": "c",
            "major": 4,
            "minor": 53,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty54",
            "type": "c",
            "major": 4,
            "minor": 54,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty55",
            "type": "c",
            "major": 4,
            "minor": 55,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty56",
            "type": "c",
            "major": 4,
            "minor": 56,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty57",
            "type": "c",
            "major": 4,
            "minor": 57,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty58",
            "type": "c",
            "major": 4,
            "minor": 58,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty59",
            "type": "c",
            "major": 4,
            "minor": 59,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty6",
            "type": "c",
            "major": 4,
            "minor": 6,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty60",
            "type": "c",
            "major": 4,
            "minor": 60,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty61",
            "type": "c",
            "major": 4,
            "minor": 61,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty62",
            "type": "c",
            "major": 4,
            "minor": 62,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty63",
            "type": "c",
            "major": 4,
            "minor": 63,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty7",
            "type": "c",
            "major": 4,
            "minor": 7,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty8",
            "type": "c",
            "major": 4,
            "minor": 8,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/tty9",
            "type": "c",
            "major": 4,
            "minor": 9,
            "fileMode": 400,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/ttyS0",
            "type": "c",
            "major": 4,
            "minor": 64,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS1",
            "type": "c",
            "major": 4,
            "minor": 65,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS10",
            "type": "c",
            "major": 4,
            "minor": 74,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS11",
            "type": "c",
            "major": 4,
            "minor": 75,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS12",
            "type": "c",
            "major": 4,
            "minor": 76,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS13",
            "type": "c",
            "major": 4,
            "minor": 77,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS14",
            "type": "c",
            "major": 4,
            "minor": 78,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS15",
            "type": "c",
            "major": 4,
            "minor": 79,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS16",
            "type": "c",
            "major": 4,
            "minor": 80,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS17",
            "type": "c",
            "major": 4,
            "minor": 81,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS18",
            "type": "c",
            "major": 4,
            "minor": 82,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS19",
            "type": "c",
            "major": 4,
            "minor": 83,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS2",
            "type": "c",
            "major": 4,
            "minor": 66,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS20",
            "type": "c",
            "major": 4,
            "minor": 84,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS21",
            "type": "c",
            "major": 4,
            "minor": 85,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS22",
            "type": "c",
            "major": 4,
            "minor": 86,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS23",
            "type": "c",
            "major": 4,
            "minor": 87,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS24",
            "type": "c",
            "major": 4,
            "minor": 88,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS25",
            "type": "c",
            "major": 4,
            "minor": 89,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS26",
            "type": "c",
            "major": 4,
            "minor": 90,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS27",
            "type": "c",
            "major": 4,
            "minor": 91,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS28",
            "type": "c",
            "major": 4,
            "minor": 92,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS29",
            "type": "c",
            "major": 4,
            "minor": 93,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS3",
            "type": "c",
            "major": 4,
            "minor": 67,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS30",
            "type": "c",
            "major": 4,
            "minor": 94,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS31",
            "type": "c",
            "major": 4,
            "minor": 95,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS4",
            "type": "c",
            "major": 4,
            "minor": 68,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS5",
            "type": "c",
            "major": 4,
            "minor": 69,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS6",
            "type": "c",
            "major": 4,
            "minor": 70,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS7",
            "type": "c",
            "major": 4,
            "minor": 71,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS8",
            "type": "c",
            "major": 4,
            "minor": 72,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/ttyS9",
            "type": "c",
            "major": 4,
            "minor": 73,
            "fileMode": 432,
            "uid": 0,
            "gid": 18
          },
          {
            "path": "/dev/udmabuf",
            "type": "c",
            "major": 10,
            "minor": 125,
            "fileMode": 432,
            "uid": 0,
            "gid": 36
          },
          {
            "path": "/dev/uhid",
            "type": "c",
            "major": 10,
            "minor": 239,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/uinput",
            "type": "c",
            "major": 10,
            "minor": 223,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/urandom",
            "type": "c",
            "major": 1,
            "minor": 9,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/usbmon0",
            "type": "c",
            "major": 243,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/usbmon1",
            "type": "c",
            "major": 243,
            "minor": 1,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/usbmon2",
            "type": "c",
            "major": 243,
            "minor": 2,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/userfaultfd",
            "type": "c",
            "major": 10,
            "minor": 126,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/vcs",
            "type": "c",
            "major": 7,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcs1",
            "type": "c",
            "major": 7,
            "minor": 1,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcs2",
            "type": "c",
            "major": 7,
            "minor": 2,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcs3",
            "type": "c",
            "major": 7,
            "minor": 3,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcs4",
            "type": "c",
            "major": 7,
            "minor": 4,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcs5",
            "type": "c",
            "major": 7,
            "minor": 5,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcs6",
            "type": "c",
            "major": 7,
            "minor": 6,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsa",
            "type": "c",
            "major": 7,
            "minor": 128,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsa1",
            "type": "c",
            "major": 7,
            "minor": 129,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsa2",
            "type": "c",
            "major": 7,
            "minor": 130,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsa3",
            "type": "c",
            "major": 7,
            "minor": 131,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsa4",
            "type": "c",
            "major": 7,
            "minor": 132,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsa5",
            "type": "c",
            "major": 7,
            "minor": 133,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsa6",
            "type": "c",
            "major": 7,
            "minor": 134,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsu",
            "type": "c",
            "major": 7,
            "minor": 64,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsu1",
            "type": "c",
            "major": 7,
            "minor": 65,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsu2",
            "type": "c",
            "major": 7,
            "minor": 66,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsu3",
            "type": "c",
            "major": 7,
            "minor": 67,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsu4",
            "type": "c",
            "major": 7,
            "minor": 68,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsu5",
            "type": "c",
            "major": 7,
            "minor": 69,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vcsu6",
            "type": "c",
            "major": 7,
            "minor": 70,
            "fileMode": 432,
            "uid": 0,
            "gid": 5
          },
          {
            "path": "/dev/vfio/vfio",
            "type": "c",
            "major": 10,
            "minor": 196,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/vga_arbiter",
            "type": "c",
            "major": 10,
            "minor": 127,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/vhci",
            "type": "c",
            "major": 10,
            "minor": 137,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/vhost-net",
            "type": "c",
            "major": 10,
            "minor": 238,
            "fileMode": 384,
            "uid": 0,
            "gid": 36
          },
          {
            "path": "/dev/vhost-vsock",
            "type": "c",
            "major": 10,
            "minor": 241,
            "fileMode": 384,
            "uid": 0,
            "gid": 36
          },
          {
            "path": "/dev/watchdog",
            "type": "c",
            "major": 10,
            "minor": 130,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/watchdog0",
            "type": "c",
            "major": 246,
            "minor": 0,
            "fileMode": 384,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/zero",
            "type": "c",
            "major": 1,
            "minor": 5,
            "fileMode": 438,
            "uid": 0,
            "gid": 0
          },
          {
            "path": "/dev/zram0",
            "type": "b",
            "major": 252,
            "minor": 0,
            "fileMode": 432,
            "uid": 0,
            "gid": 6
          }
        ],
        "rootfsPropagation": "rshared"
      }
    }
  }
}`)

	fmt.Println("jsonparser test2 - multiple containers")

	// crictl pods --name bpfman-daemon-hf5gv -o json
	podId, err := jsonparser.GetString(podInfo, "items", "[0]", "id")
	fmt.Println("podId:", podId, "err:", err)

	// crictl ps --name bpfman --pod ffde0b824a13e5c81699b3059dc0bfe39ca8d8e6b7c6966c8d2562d00741ce99 -o json
	// containerId, err := jsonparser.GetString(containerInfo, "containers", "[0]", "id")
	// fmt.Println("containerId:", containerId, "err:", err)

	var containerIds []string

	for containerIndex := 0; ; containerIndex++ {
		containerId, err := jsonparser.GetString(containerInfo, "containers", "["+strconv.Itoa(containerIndex)+"]", "id")
		if err != nil {
			break
		}
		containerIds = append(containerIds, containerId)
	}

	fmt.Println(len(containerIds), "containers were found")

	for i, containerId := range containerIds {
		fmt.Println("containerId", i, ":", containerId)
	}

	// crictl inspect -o json c1ed727676f3ac5c652b706e4576d1ff7680dfb3fd2dc60cfd9cc87cca6d7e01
	containerPid, err := jsonparser.GetInt(containerData1, "info", "pid")
	fmt.Println("containerPid0:", containerPid, "err:", err)

	// crictl inspect -o json ee31cab3b7ff9aa60fc4d686fec84881f79fb4194ccf4eb7dda793db04ad48db
	containerPid, err = jsonparser.GetInt(containerData2, "info", "pid")
	fmt.Println("containerPid1:", containerPid, "err:", err)
}
