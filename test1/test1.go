package main

import (
	"fmt"
	"strconv"

	"github.com/buger/jsonparser"
)

func main() {

	// crictl pods --name bpfman-operator-65747dc769-pjztg -o json
	podInfo := []byte(`{
  "items": [
    {
      "id": "655b0ad6e26c0403c00ef9ab69c399e4e86f92d6bd3ad22a286849bf310b31f3",
      "metadata": {
        "name": "bpfman-operator-65747dc769-pjztg",
        "uid": "4cad64d0-7a36-452a-8a08-bd3a694cdad5",
        "namespace": "bpfman",
        "attempt": 0
      },
      "state": "SANDBOX_READY",
      "createdAt": "1702671154122345580",
      "labels": {
        "control-plane": "controller-manager",
        "io.kubernetes.pod.name": "bpfman-operator-65747dc769-pjztg",
        "io.kubernetes.pod.namespace": "bpfman",
        "io.kubernetes.pod.uid": "4cad64d0-7a36-452a-8a08-bd3a694cdad5",
        "pod-template-hash": "65747dc769"
      },
      "annotations": {
        "kubectl.kubernetes.io/default-container": "manager",
        "kubernetes.io/config.seen": "2023-12-15T20:12:33.780038912Z",
        "kubernetes.io/config.source": "api"
      },
      "runtimeHandler": ""
    }
  ]
}`)

	// crictl ps --name bpfman-operator --pod 655b0ad6e26c0403c00ef9ab69c399e4e86f92d6bd3ad22a286849bf310b31f3 -o json
	containerInfo := []byte(`{
  "containers": [
    {
      "id": "b1f06ea545e81d89dc503414d20a33f1b3f3eca71e3a4344fd16ddc202cc8129",
      "podSandboxId": "655b0ad6e26c0403c00ef9ab69c399e4e86f92d6bd3ad22a286849bf310b31f3",
      "metadata": {
        "name": "bpfman-operator",
        "attempt": 0
      },
      "image": {
        "image": "sha256:8bab0f36b56c1726bffd8ff7f346207c4e269349386c403e01520f5ae109a4e9",
        "annotations": {
        },
        "userSpecifiedImage": ""
      },
      "imageRef": "sha256:8bab0f36b56c1726bffd8ff7f346207c4e269349386c403e01520f5ae109a4e9",
      "state": "CONTAINER_RUNNING",
      "createdAt": "1702671156599632356",
      "labels": {
        "io.kubernetes.container.name": "bpfman-operator",
        "io.kubernetes.pod.name": "bpfman-operator-65747dc769-pjztg",
        "io.kubernetes.pod.namespace": "bpfman",
        "io.kubernetes.pod.uid": "4cad64d0-7a36-452a-8a08-bd3a694cdad5"
      },
      "annotations": {
        "io.kubernetes.container.hash": "776d5c15",
        "io.kubernetes.container.restartCount": "0",
        "io.kubernetes.container.terminationMessagePath": "/dev/termination-log",
        "io.kubernetes.container.terminationMessagePolicy": "File",
        "io.kubernetes.pod.terminationGracePeriod": "10"
      }
    }
  ]
}`)

	// crictl inspect -o json b1f06ea545e81d89dc503414d20a33f1b3f3eca71e3a4344fd16ddc202cc8129
	containerData := []byte(`{
  "status": {
    "id": "b1f06ea545e81d89dc503414d20a33f1b3f3eca71e3a4344fd16ddc202cc8129",
    "metadata": {
      "attempt": 0,
      "name": "bpfman-operator"
    },
    "state": "CONTAINER_RUNNING",
    "createdAt": "2023-12-15T20:12:36.599632356Z",
    "startedAt": "2023-12-15T20:12:36.78151617Z",
    "finishedAt": "0001-01-01T00:00:00Z",
    "exitCode": 0,
    "image": {
      "annotations": {},
      "image": "quay.io/bpfman/bpfman-operator:latest",
      "userSpecifiedImage": ""
    },
    "imageRef": "docker.io/library/import-2023-12-15@sha256:c2e072951a1e9c799f4071f97d4e246fc4c747ea67339f41951f9af2c19d5984",
    "reason": "",
    "message": "",
    "labels": {
      "io.kubernetes.container.name": "bpfman-operator",
      "io.kubernetes.pod.name": "bpfman-operator-65747dc769-pjztg",
      "io.kubernetes.pod.namespace": "bpfman",
      "io.kubernetes.pod.uid": "4cad64d0-7a36-452a-8a08-bd3a694cdad5"
    },
    "annotations": {
      "io.kubernetes.container.hash": "776d5c15",
      "io.kubernetes.container.restartCount": "0",
      "io.kubernetes.container.terminationMessagePath": "/dev/termination-log",
      "io.kubernetes.container.terminationMessagePolicy": "File",
      "io.kubernetes.pod.terminationGracePeriod": "10"
    },
    "mounts": [
      {
        "containerPath": "/var/run/secrets/kubernetes.io/serviceaccount",
        "gidMappings": [],
        "hostPath": "/var/lib/kubelet/pods/4cad64d0-7a36-452a-8a08-bd3a694cdad5/volumes/kubernetes.io~projected/kube-api-access-sg2p4",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": true,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/etc/hosts",
        "gidMappings": [],
        "hostPath": "/var/lib/kubelet/pods/4cad64d0-7a36-452a-8a08-bd3a694cdad5/etc-hosts",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      },
      {
        "containerPath": "/dev/termination-log",
        "gidMappings": [],
        "hostPath": "/var/lib/kubelet/pods/4cad64d0-7a36-452a-8a08-bd3a694cdad5/containers/bpfman-operator/08cf3736",
        "propagation": "PROPAGATION_PRIVATE",
        "readonly": false,
        "selinuxRelabel": false,
        "uidMappings": []
      }
    ],
    "logPath": "/var/log/pods/bpfman_bpfman-operator-65747dc769-pjztg_4cad64d0-7a36-452a-8a08-bd3a694cdad5/bpfman-operator/0.log",
    "resources": {
      "linux": {
        "cpuPeriod": "100000",
        "cpuQuota": "50000",
        "cpuShares": "10",
        "cpusetCpus": "",
        "cpusetMems": "",
        "hugepageLimits": [],
        "memoryLimitInBytes": "134217728",
        "memorySwapLimitInBytes": "134217728",
        "oomScoreAdj": "999",
        "unified": {}
      },
      "windows": null
    }
  },
  "info": {
    "sandboxID": "655b0ad6e26c0403c00ef9ab69c399e4e86f92d6bd3ad22a286849bf310b31f3",
    "pid": 2092,
    "removing": false,
    "snapshotKey": "b1f06ea545e81d89dc503414d20a33f1b3f3eca71e3a4344fd16ddc202cc8129",
    "snapshotter": "overlayfs",
    "runtimeType": "io.containerd.runc.v2",
    "runtimeOptions": {
      "systemd_cgroup": true
    },
    "config": {
      "metadata": {
        "name": "bpfman-operator"
      },
      "image": {
        "image": "sha256:8bab0f36b56c1726bffd8ff7f346207c4e269349386c403e01520f5ae109a4e9"
      },
      "command": [
        "/bpfman-operator"
      ],
      "args": [
        "--health-probe-bind-address=:8081",
        "--metrics-bind-address=127.0.0.1:8080",
        "--leader-elect"
      ],
      "envs": [
        {
          "key": "GO_LOG",
          "value": "debug"
        },
        {
          "key": "KUBERNETES_SERVICE_PORT",
          "value": "443"
        },
        {
          "key": "KUBERNETES_SERVICE_PORT_HTTPS",
          "value": "443"
        },
        {
          "key": "KUBERNETES_PORT_443_TCP_ADDR",
          "value": "10.96.0.1"
        },
        {
          "key": "KUBERNETES_PORT_443_TCP",
          "value": "tcp://10.96.0.1:443"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_PORT",
          "value": "8443"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP",
          "value": "tcp://10.96.167.210:8443"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_PORT",
          "value": "8443"
        },
        {
          "key": "KUBERNETES_SERVICE_HOST",
          "value": "10.96.0.1"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_HOST",
          "value": "10.96.167.210"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_ADDR",
          "value": "10.96.167.210"
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
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT",
          "value": "tcp://10.96.167.210:8443"
        },
        {
          "key": "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_PROTO",
          "value": "tcp"
        },
        {
          "key": "KUBERNETES_PORT",
          "value": "tcp://10.96.0.1:443"
        }
      ],
      "mounts": [
        {
          "container_path": "/var/run/secrets/kubernetes.io/serviceaccount",
          "host_path": "/var/lib/kubelet/pods/4cad64d0-7a36-452a-8a08-bd3a694cdad5/volumes/kubernetes.io~projected/kube-api-access-sg2p4",
          "readonly": true
        },
        {
          "container_path": "/etc/hosts",
          "host_path": "/var/lib/kubelet/pods/4cad64d0-7a36-452a-8a08-bd3a694cdad5/etc-hosts"
        },
        {
          "container_path": "/dev/termination-log",
          "host_path": "/var/lib/kubelet/pods/4cad64d0-7a36-452a-8a08-bd3a694cdad5/containers/bpfman-operator/08cf3736"
        }
      ],
      "labels": {
        "io.kubernetes.container.name": "bpfman-operator",
        "io.kubernetes.pod.name": "bpfman-operator-65747dc769-pjztg",
        "io.kubernetes.pod.namespace": "bpfman",
        "io.kubernetes.pod.uid": "4cad64d0-7a36-452a-8a08-bd3a694cdad5"
      },
      "annotations": {
        "io.kubernetes.container.hash": "776d5c15",
        "io.kubernetes.container.restartCount": "0",
        "io.kubernetes.container.terminationMessagePath": "/dev/termination-log",
        "io.kubernetes.container.terminationMessagePolicy": "File",
        "io.kubernetes.pod.terminationGracePeriod": "10"
      },
      "log_path": "bpfman-operator/0.log",
      "linux": {
        "resources": {
          "cpu_period": 100000,
          "cpu_quota": 50000,
          "cpu_shares": 10,
          "memory_limit_in_bytes": 134217728,
          "oom_score_adj": 999,
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
          "capabilities": {
            "drop_capabilities": [
              "ALL"
            ]
          },
          "namespace_options": {
            "pid": 1
          },
          "run_as_user": {
            "value": 65532
          },
          "no_new_privs": true,
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
          "uid": 65532,
          "gid": 65532,
          "additionalGids": [
            65532
          ]
        },
        "args": [
          "/bpfman-operator",
          "--health-probe-bind-address=:8081",
          "--metrics-bind-address=127.0.0.1:8080",
          "--leader-elect"
        ],
        "env": [
          "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
          "HOSTNAME=bpfman-operator-65747dc769-pjztg",
          "SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt",
          "GO_LOG=debug",
          "KUBERNETES_SERVICE_PORT=443",
          "KUBERNETES_SERVICE_PORT_HTTPS=443",
          "KUBERNETES_PORT_443_TCP_ADDR=10.96.0.1",
          "KUBERNETES_PORT_443_TCP=tcp://10.96.0.1:443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_PORT=8443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP=tcp://10.96.167.210:8443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_PORT=8443",
          "KUBERNETES_SERVICE_HOST=10.96.0.1",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_HOST=10.96.167.210",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_ADDR=10.96.167.210",
          "KUBERNETES_PORT_443_TCP_PROTO=tcp",
          "KUBERNETES_PORT_443_TCP_PORT=443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_SERVICE_PORT_HTTPS=8443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT=tcp://10.96.167.210:8443",
          "BPFMAN_CONTROLLER_MANAGER_METRICS_SERVICE_PORT_8443_TCP_PROTO=tcp",
          "KUBERNETES_PORT=tcp://10.96.0.1:443"
        ],
        "cwd": "/",
        "capabilities": {},
        "noNewPrivileges": true,
        "oomScoreAdj": 999
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
            "ro"
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
            "ro"
          ]
        },
        {
          "destination": "/etc/hosts",
          "type": "bind",
          "source": "/var/lib/kubelet/pods/4cad64d0-7a36-452a-8a08-bd3a694cdad5/etc-hosts",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/dev/termination-log",
          "type": "bind",
          "source": "/var/lib/kubelet/pods/4cad64d0-7a36-452a-8a08-bd3a694cdad5/containers/bpfman-operator/08cf3736",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/etc/hostname",
          "type": "bind",
          "source": "/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/655b0ad6e26c0403c00ef9ab69c399e4e86f92d6bd3ad22a286849bf310b31f3/hostname",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/etc/resolv.conf",
          "type": "bind",
          "source": "/var/lib/containerd/io.containerd.grpc.v1.cri/sandboxes/655b0ad6e26c0403c00ef9ab69c399e4e86f92d6bd3ad22a286849bf310b31f3/resolv.conf",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/dev/shm",
          "type": "bind",
          "source": "/run/containerd/io.containerd.grpc.v1.cri/sandboxes/655b0ad6e26c0403c00ef9ab69c399e4e86f92d6bd3ad22a286849bf310b31f3/shm",
          "options": [
            "rbind",
            "rprivate",
            "rw"
          ]
        },
        {
          "destination": "/var/run/secrets/kubernetes.io/serviceaccount",
          "type": "bind",
          "source": "/var/lib/kubelet/pods/4cad64d0-7a36-452a-8a08-bd3a694cdad5/volumes/kubernetes.io~projected/kube-api-access-sg2p4",
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
        "io.kubernetes.cri.container-name": "bpfman-operator",
        "io.kubernetes.cri.container-type": "container",
        "io.kubernetes.cri.image-name": "quay.io/bpfman/bpfman-operator:latest",
        "io.kubernetes.cri.sandbox-id": "655b0ad6e26c0403c00ef9ab69c399e4e86f92d6bd3ad22a286849bf310b31f3",
        "io.kubernetes.cri.sandbox-name": "bpfman-operator-65747dc769-pjztg",
        "io.kubernetes.cri.sandbox-namespace": "bpfman",
        "io.kubernetes.cri.sandbox-uid": "4cad64d0-7a36-452a-8a08-bd3a694cdad5"
      },
      "linux": {
        "resources": {
          "devices": [
            {
              "allow": false,
              "access": "rwm"
            }
          ],
          "memory": {
            "limit": 134217728,
            "swap": 134217728
          },
          "cpu": {
            "shares": 10,
            "quota": 50000,
            "period": 100000
          }
        },
        "cgroupsPath": "kubelet-kubepods-burstable-pod4cad64d0_7a36_452a_8a08_bd3a694cdad5.slice:cri-containerd:b1f06ea545e81d89dc503414d20a33f1b3f3eca71e3a4344fd16ddc202cc8129",
        "namespaces": [
          {
            "type": "pid"
          },
          {
            "type": "ipc",
            "path": "/proc/2001/ns/ipc"
          },
          {
            "type": "uts",
            "path": "/proc/2001/ns/uts"
          },
          {
            "type": "mount"
          },
          {
            "type": "network",
            "path": "/proc/2001/ns/net"
          }
        ],
        "maskedPaths": [
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
        "readonlyPaths": [
          "/proc/bus",
          "/proc/fs",
          "/proc/irq",
          "/proc/sys",
          "/proc/sysrq-trigger"
        ]
      }
    }
  }
}`)

	fmt.Println("hello world")

	// crictl pods --name bpfman-operator-65747dc769-pjztg -o json
	podId, err := jsonparser.GetString(podInfo, "items", "[0]", "id")
	fmt.Println("podId:", podId, "err:", err)

	// crictl ps --name bpfman-operator --pod 655b0ad6e26c0403c00ef9ab69c399e4e86f92d6bd3ad22a286849bf310b31f3 -o json
	containerId, err := jsonparser.GetString(containerInfo, "containers", "[0]", "id")
	fmt.Println("containerId:", containerId, "err:", err)

	// crictl inspect -o json b1f06ea545e81d89dc503414d20a33f1b3f3eca71e3a4344fd16ddc202cc8129
	containerPid, err := jsonparser.GetInt(containerData, "info", "pid")
	fmt.Println("containerPid:", containerPid, "err:", err)

	containerPidStr := strconv.FormatInt(containerPid, 10)
	fmt.Println("containerPidStr:", containerPidStr)

	containerPidInt, err := strconv.ParseInt(containerPidStr, 10, 32)
	fmt.Println("containerPidInt:", int32(containerPidInt), "err:", err)

}
