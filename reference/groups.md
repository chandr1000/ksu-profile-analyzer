# Android GIDs (KernelSU `Groups.kt`)

Verbatim from `manager/app/src/main/java/.../profile/Groups.kt`. All three KSU-family forks currently ship the same table.

**Source files**:

- upstream: <https://raw.githubusercontent.com/tiann/KernelSU/main/manager/app/src/main/java/me/weishu/kernelsu/profile/Groups.kt>
- KSU-Next: <https://raw.githubusercontent.com/KernelSU-Next/KernelSU-Next/main/manager/app/src/main/java/me/weishu/kernelsu/profile/Groups.kt>
- SukiSU-Ultra: <https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/manager/app/src/main/java/com/sukisu/ultra/profile/Groups.kt>

## Mapping Android permissions → GIDs

| Android permission | → GID (name = number) |
|---|---|
| `INTERNET` | `inet` (3003) |
| `ACCESS_NETWORK_STATE` | (no group — uses `capget` directly) |
| `CHANGE_NETWORK_STATE`, tethering | `net_admin` (3005) |
| `BLUETOOTH_ADMIN` | `net_bt_admin` (3001) |
| `BLUETOOTH` | `net_bt` (3002) |
| `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION` (GPS) | `gps` (1021) (system only; userland apps don't get gps group) |
| `CAMERA` | `camera` (1006) (system only) |
| `RECORD_AUDIO` | `audio` (1005) (system only) |
| `READ_EXTERNAL_STORAGE` | `sdcard_r` (1028), `everybody` (9997) |
| `WRITE_EXTERNAL_STORAGE` | `sdcard_rw` (1015), `media_rw` (1023) |
| `MOUNT_UNMOUNT_FILESYSTEMS` | `mount` (1009) (system only) |
| `VIBRATE` | (no group) |
| `WAKE_LOCK` | `wakelock` (3010) |
| `READ_PROC` | `readproc` (3009) (rare) |
| `DUMP`, `READ_LOGS` | `log` (1007), `logd` (1036) |
| `SET_TIME` | (no group — uses `CAP_SYS_TIME` capability) |

For userland apps (uid 10000+), most groups are added automatically by the system based on declared permissions. The KernelSU root profile's `groups` field **only affects the `su` process spawned by the app** — it does not affect the app's own runtime permissions.

## Full GID table

| # | Name | GID | Display | Description |
|---|---|---|---|---|
| 1 | `ROOT` | 0 | root | traditional unix root user |
| 2 | `DAEMON` | 1 | daemon | Traditional unix daemon owner |
| 3 | `BIN` | 2 | bin | Traditional unix binaries owner |
| 4 | `SYS` | 3 | sys | A group with the same gid on Linux/macOS/Android |
| 5 | `SYSTEM` | 1000 | system | system server |
| 6 | `RADIO` | 1001 | radio | telephony subsystem, RIL |
| 7 | `BLUETOOTH` | 1002 | bluetooth | bluetooth subsystem |
| 8 | `GRAPHICS` | 1003 | graphics | graphics devices |
| 9 | `INPUT` | 1004 | input | input devices |
| 10 | `AUDIO` | 1005 | audio | audio devices |
| 11 | `CAMERA` | 1006 | camera | camera devices |
| 12 | `LOG` | 1007 | log | log devices |
| 13 | `COMPASS` | 1008 | compass | compass device |
| 14 | `MOUNT` | 1009 | mount | mountd socket |
| 15 | `WIFI` | 1010 | wifi | wifi subsystem |
| 16 | `ADB` | 1011 | adb | android debug bridge (adbd) |
| 17 | `INSTALL` | 1012 | install | group for installing packages |
| 18 | `MEDIA` | 1013 | media | mediaserver process |
| 19 | `DHCP` | 1014 | dhcp | dhcp client |
| 20 | `SDCARD_RW` | 1015 | sdcard_rw | external storage write access |
| 21 | `VPN` | 1016 | vpn | vpn system |
| 22 | `KEYSTORE` | 1017 | keystore | keystore subsystem |
| 23 | `USB` | 1018 | usb | USB devices |
| 24 | `DRM` | 1019 | drm | DRM server |
| 25 | `MDNSR` | 1020 | mdnsr | MulticastDNSResponder (service discovery) |
| 26 | `GPS` | 1021 | gps | GPS daemon |
| 27 | `UNUSED1` | 1022 | unused1 | deprecated, DO NOT USE |
| 28 | `MEDIA_RW` | 1023 | media_rw | internal media storage write access |
| 29 | `MTP` | 1024 | mtp | MTP USB driver access |
| 30 | `UNUSED2` | 1025 | unused2 | deprecated, DO NOT USE |
| 31 | `DRMRPC` | 1026 | drmrpc | group for drm rpc |
| 32 | `NFC` | 1027 | nfc | nfc subsystem |
| 33 | `SDCARD_R` | 1028 | sdcard_r | external storage read access |
| 34 | `CLAT` | 1029 | clat | clat part of nat464 |
| 35 | `LOOP_RADIO` | 1030 | loop_radio | loop radio devices |
| 36 | `MEDIA_DRM` | 1031 | media_drm | MediaDrm plugins |
| 37 | `PACKAGE_INFO` | 1032 | package_info | access to installed package details |
| 38 | `SDCARD_PICS` | 1033 | sdcard_pics | external storage photos access |
| 39 | `SDCARD_AV` | 1034 | sdcard_av | external storage audio/video access |
| 40 | `SDCARD_ALL` | 1035 | sdcard_all | access all users external storage |
| 41 | `LOGD` | 1036 | logd | log daemon |
| 42 | `SHARED_RELRO` | 1037 | shared_relro | creator of shared GNU RELRO files |
| 43 | `DBUS` | 1038 | dbus | dbus-daemon IPC broker process |
| 44 | `TLSDATE` | 1039 | tlsdate | tlsdate unprivileged user |
| 45 | `MEDIA_EX` | 1040 | media_ex | mediaextractor process |
| 46 | `AUDIOSERVER` | 1041 | audioserver | audioserver process |
| 47 | `METRICS_COLL` | 1042 | metrics_coll | metrics_collector process |
| 48 | `METRICSD` | 1043 | metricsd | metricsd process |
| 49 | `WEBSERV` | 1044 | webserv | webservd process |
| 50 | `DEBUGGERD` | 1045 | debuggerd | debuggerd unprivileged user |
| 51 | `MEDIA_CODEC` | 1046 | media_codec | media_codec process |
| 52 | `CAMERASERVER` | 1047 | cameraserver | cameraserver process |
| 53 | `FIREWALL` | 1048 | firewall | firewall process |
| 54 | `TRUNKS` | 1049 | trunks | trunksd process |
| 55 | `NVRAM` | 1050 | nvram | nvram daemon |
| 56 | `DNS` | 1051 | dns | DNS resolution daemon (system: netd) |
| 57 | `DNS_TETHER` | 1052 | dns_tether | DNS resolution daemon (tether: dnsmasq) |
| 58 | `WEBVIEW_ZYGOTE` | 1053 | webview_zygote | WebView zygote process |
| 59 | `VEHICLE_NETWORK` | 1054 | vehicle_network | Vehicle network service |
| 60 | `MEDIA_AUDIO` | 1055 | media_audio | GID for audio files on internal media storage |
| 61 | `MEDIA_VIDEO` | 1056 | media_video | GID for video files on internal media storage |
| 62 | `MEDIA_IMAGE` | 1057 | media_image | GID for image files on internal media storage |
| 63 | `TOMBSTONED` | 1058 | tombstoned | tombstoned user |
| 64 | `MEDIA_OBB` | 1059 | media_obb | GID for OBB files on internal media storage |
| 65 | `ESE` | 1060 | ese | embedded secure element (eSE) subsystem |
| 66 | `OTA_UPDATE` | 1061 | ota_update | resource tracking UID for OTA updates |
| 67 | `AUTOMOTIVE_EVS` | 1062 | automotive_evs | Automotive rear and surround view system |
| 68 | `LOWPAN` | 1063 | lowpan | LoWPAN subsystem |
| 69 | `HSM` | 1064 | lowpan | hardware security module subsystem |
| 70 | `RESERVED_DISK` | 1065 | reserved_disk | GID that has access to reserved disk space |
| 71 | `STATSD` | 1066 | statsd | statsd daemon |
| 72 | `INCIDENTD` | 1067 | incidentd | incidentd daemon |
| 73 | `SECURE_ELEMENT` | 1068 | secure_element | secure element subsystem |
| 74 | `LMKD` | 1069 | lmkd | low memory killer daemon |
| 75 | `LLKD` | 1070 | llkd | live lock daemon |
| 76 | `IORAPD` | 1071 | iorapd | input/output readahead and pin daemon |
| 77 | `GPU_SERVICE` | 1072 | gpu_service | GPU service daemon |
| 78 | `NETWORK_STACK` | 1073 | network_stack | network stack service |
| 79 | `GSID` | 1074 | GSID | GSI service daemon |
| 80 | `FSVERITY_CERT` | 1075 | fsverity_cert | fs-verity key ownership in keystore |
| 81 | `CREDSTORE` | 1076 | credstore | identity credential manager service |
| 82 | `EXTERNAL_STORAGE` | 1077 | external_storage | Full external storage access including USB OTG volumes |
| 83 | `EXT_DATA_RW` | 1078 | ext_data_rw | GID for app-private data directories on external storage |
| 84 | `EXT_OBB_RW` | 1079 | ext_obb_rw | GID for OBB directories on external storage |
| 85 | `CONTEXT_HUB` | 1080 | context_hub | GID for access to the Context Hub |
| 86 | `VIRTUALIZATIONSERVICE` | 1081 | virtualizationservice | VirtualizationService daemon |
| 87 | `ARTD` | 1082 | artd | ART Service daemon |
| 88 | `UWB` | 1083 | uwb | UWB subsystem |
| 89 | `THREAD_NETWORK` | 1084 | thread_network | Thread Network subsystem |
| 90 | `DICED` | 1085 | diced | Android's DICE daemon |
| 91 | `DMESGD` | 1086 | dmesgd | dmesg parsing daemon for kernel report collection |
| 92 | `JC_WEAVER` | 1087 | jc_weaver | Javacard Weaver HAL - to manage omapi ARA rules |
| 93 | `JC_STRONGBOX` | 1088 | jc_strongbox | Javacard Strongbox HAL - to manage omapi ARA rules |
| 94 | `JC_IDENTITYCRED` | 1089 | jc_identitycred | Javacard Identity Cred HAL - to manage omapi ARA rules |
| 95 | `SDK_SANDBOX` | 1090 | sdk_sandbox | SDK sandbox virtual UID |
| 96 | `SECURITY_LOG_WRITER` | 1091 | security_log_writer | write to security log |
| 97 | `PRNG_SEEDER` | 1092 | prng_seeder | PRNG seeder daemon |
| 98 | `UPROBESTATS` | 1093 | uprobestats | uid for uprobestats |
| 99 | `CROS_EC` | 1094 | cros_ec | uid for accessing ChromeOS EC (cros_ec) |
| 100 | `MMD` | 1095 | mmd | uid for memory management daemon |
| 101 | `SHELL` | 2000 | shell | adb and debug shell user |
| 102 | `CACHE` | 2001 | cache | cache access |
| 103 | `DIAG` | 2002 | diag | access to diagnostic resources |
| 104 | `NET_BT_ADMIN` | 3001 | net_bt_admin | bluetooth: create any socket |
| 105 | `NET_BT` | 3002 | net_bt | bluetooth: create sco, rfcomm or l2cap sockets |
| 106 | `INET` | 3003 | inet | can create AF_INET and AF_INET6 sockets |
| 107 | `NET_RAW` | 3004 | net_raw | can create raw INET sockets |
| 108 | `NET_ADMIN` | 3005 | net_admin | can configure interfaces and routing tables |
| 109 | `NET_BW_STATS` | 3006 | net_bw_stats | read bandwidth statistics |
| 110 | `NET_BW_ACCT` | 3007 | net_bw_acct | change bandwidth statistics accounting |
| 111 | `NET_BT_STACK` | 3008 | net_bt_stack | access to various bluetooth management functions |
| 112 | `READPROC` | 3009 | readproc | Allow /proc read access |
| 113 | `WAKELOCK` | 3010 | wakelock | Allow system wakelock read/write access |
| 114 | `UHID` | 3011 | uhid | Allow read/write to /dev/uhid node |
| 115 | `READTRACEFS` | 3012 | readtracefs | Allow tracefs read |
| 116 | `VIRTUALMACHINE` | 3013 | virtualmachine | Allows VMs to tune for performance |
| 117 | `EVERYBODY` | 9997 | everybody | Shared external storage read/write |
| 118 | `MISC` | 9998 | misc | Access to misc storage |
| 119 | `NOBODY` | 9999 | nobody | Reserved |
| 120 | `APP` | 10000 | app | Access to app data |

## Skill usage notes

- The `groups` field in the Profile is a `List<Int>` — pass GIDs as integers (e.g. `3003`, not `"inet"`).
- Do NOT include `ROOT (0)` in the groups list — it's already implied by `gid: 0`.
- For root apps that need network access (e.g. firewall tools), include `3003` (inet) and `3004` (net_raw).
- For shell-like root access, mirror the ADB shell's supplementary groups: `3003, 3004, 3005, 1007, 1015, 1028, 1078, 1079, 3001, 3002, 3006, 3009, 3011, 3012`. **Use this only if the user explicitly asks for "shell-like" privileges.**
