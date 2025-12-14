#!/usr/bin/env python3
"""
eBPF-based System Call Logger
This program captures syscall-level provenance, writes to JSONL, and ships to Elasticsearch
It is designed to be quiet by default but supports debug printing for live inspection
"""

from bcc import BPF
import json
import time
import sys
import errno
from datetime import datetime
from elasticsearch import Elasticsearch, helpers
from elasticsearch import ElasticsearchWarning
import argparse
import threading
import os

# Config
DEBUG = False
MAX_DEBUG_LEN = 200    # truncate long output for readability

# eBPF program

bpf_program = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

// ---------------- Structures ----------------

struct enter_data_t {
    char filename[256];
    u64  flags;
    u64  count;
};

struct event_t {
    u64 timestamp;
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[32];
    char syscall[32];
    char filename[256];

    s64 fd;
    u64 flags;
    s64 ret;

    u32 dest_ip;
    u32 dest_ipv6[4];
    u16 dest_port;
    u16 sa_family;

    u64 count;
    s64 bytes_rw;
};

// ---------------- Maps ----------------

BPF_PERF_OUTPUT(events);
BPF_HASH(open_data, u64, struct enter_data_t);
BPF_HASH(write_data, u64, struct enter_data_t);
BPF_PERCPU_ARRAY(event_heap, struct event_t, 1);

// ---------------- Helpers ----------------

static inline u32 get_ppid() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = 0;
    bpf_probe_read_kernel(&ppid, sizeof(ppid), &task->real_parent->tgid);
    return ppid;
}

static inline int should_drop(const char *filename, const char *comm) {
    if (filename[0] == 0) return 0;

    // Drop noisy kernel paths
    if (filename[0]=='/' && filename[1]=='p' && filename[2]=='r') return 1;
    if (filename[0]=='/' && filename[1]=='s' && filename[2]=='y') return 1;
    if (filename[0]=='/' && filename[1]=='d' && filename[2]=='e') return 1;

    // Drop .so
    int len = 0;
    for (int i = 0; i < 256; i++)
        if (filename[i] == 0) { len = i; break; }
    if (len > 3 && filename[len-1]=='o' && filename[len-2]=='s' && filename[len-3]=='.')
        return 1;

    // Drop systemd/dbus
    if (comm[0]=='s' && comm[1]=='y') return 1;
    if (comm[0]=='d' && comm[1]=='b' && comm[2]=='u') return 1;

    return 0;
}

static inline void submit_event(void *ctx,
                                const char *syscall,
                                const char *filename,
                                s64 fd,
                                u64 flags,
                                s64 ret,
                                u64 count,
                                s64 bytes_rw) {

    u32 zero = 0;
    struct event_t *event = event_heap.lookup(&zero);
    if (!event) return;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    event->pid = pid_tgid >> 32;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    if (should_drop(filename, event->comm))
        return;

    event->timestamp = bpf_ktime_get_ns();
    event->ppid = get_ppid();
    event->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    __builtin_memcpy(event->syscall, syscall, 32);
    if (filename)
        __builtin_memcpy(event->filename, filename, 256);
    else
        event->filename[0] = 0;

    event->fd = fd;
    event->flags = flags;
    event->ret = ret;
    event->count = count;
    event->bytes_rw = bytes_rw;

    event->dest_ip = 0;
    event->dest_port = 0;
    event->sa_family = 0;
    #pragma unroll
    for (int i=0;i<4;i++) event->dest_ipv6[i] = 0;

    events.perf_submit(ctx, event, sizeof(*event));
}

// ---------------- Syscall Probes ----------------

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    char filename[256]={};
    bpf_probe_read_user_str(filename, sizeof(filename), (void*)args->filename);
    submit_event(args, "execve", filename, 0,0,0,0,0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct enter_data_t data = {};
    bpf_probe_read_user_str(data.filename,sizeof(data.filename),(void*)args->filename);
    data.flags = args->flags;
    open_data.update(&pid_tgid,&data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct enter_data_t *data = open_data.lookup(&pid_tgid);
    if (!data) return 0;
    submit_event(args, "openat", data->filename, args->ret, data->flags, args->ret, 0,0);
    open_data.delete(&pid_tgid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct enter_data_t data = {};
    data.count = args->count;
    data.flags = args->fd;
    write_data.update(&pid_tgid, &data);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_write) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct enter_data_t *data = write_data.lookup(&pid_tgid);
    if (!data) return 0;

    if (args->ret < 10 && args->ret >= 0) { 
        write_data.delete(&pid_tgid);
        return 0; 
    }

    submit_event(args, "write", "", data->flags, 0, args->ret, data->count, args->ret);
    write_data.delete(&pid_tgid);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
    char filename[256]={};
    bpf_probe_read_user_str(filename,sizeof(filename),(void*)args->pathname);
    submit_event(args,"unlinkat",filename,0,0,0,0,0);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    u32 zero=0;
    struct event_t *ev = event_heap.lookup(&zero);
    if (!ev) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    ev->pid = pid_tgid >> 32;

    bpf_get_current_comm(ev->comm,sizeof(ev->comm));
    if (should_drop("",ev->comm)) return 0;

    ev->timestamp = bpf_ktime_get_ns();
    ev->ppid = get_ppid();
    ev->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    __builtin_memcpy(ev->syscall,"connect",8);
    ev->filename[0]=0;

    ev->fd = args->fd;

    u16 family=0;
    bpf_probe_read_user(&family,sizeof(family),args->uservaddr);
    ev->sa_family = family;

    if (family == 2) {  // IPv4
        struct sockaddr_in {
            u16 sin_family; u16 sin_port; u32 sin_addr;
        } a={};
        bpf_probe_read_user(&a,sizeof(a),args->uservaddr);
        ev->dest_port = bpf_ntohs(a.sin_port);
        ev->dest_ip = bpf_ntohl(a.sin_addr);
    }
    else if (family == 10) { // IPv6
        struct sockaddr_in6 {
            u16 sin6_family; u16 sin6_port; u32 sin6_flowinfo;
            u8 sin6_addr[16]; u32 sin6_scope_id;
        } a6={};
        bpf_probe_read_user(&a6,sizeof(a6),args->uservaddr);

        ev->dest_port = bpf_ntohs(a6.sin6_port);

        u32 raw[4]={};
        bpf_probe_read_user(&raw,sizeof(raw),&a6.sin6_addr);

        #pragma unroll
        for(int i=0;i<4;i++) ev->dest_ipv6[i]=raw[i];

        ev->dest_ip = 0;
    }

    events.perf_submit(args,ev,sizeof(*ev));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
    submit_event(args,"clone","",0,0,0,0,0);
    return 0;
}
"""

# ebpf monitor

class EBPFMonitor:

    def __init__(self, config):
        self.event_count = 0
        self.running = True
        self.es_buffer = []
        self.lock = threading.Lock()
        self.es_enabled = True

        # ES Setup
        es_host = config.get("es_host","localhost:9200")
        if not es_host.startswith(("http://","https://")):
            es_host = f"https://{es_host}"

        try:
            # ES security warnings are noisy for local demos
            import warnings
            warnings.filterwarnings("ignore", category=ElasticsearchWarning)

            self.es = Elasticsearch(
                [es_host],
                basic_auth=(config.get("es_user"),config.get("es_password")),
                verify_certs=False, ssl_show_warn=False
            )
            self.es.info()  # light sanity check
        except Exception as e:
            print(f"[!] Elasticsearch unavailable ({e}). Continuing with file-only logging.")
            self.es_enabled = False
            self.es = None

        self.es_index = config.get("es_index","ebpf-events")
        self.batch_size = config.get("batch_size",500)

        if self.es_enabled:
            self._create_index_template()

        # Local log file
        events_dir = config.get("events_dir","/home/student/system-auditing-tester/ebpf_out")
        os.makedirs(events_dir,exist_ok=True)
        events_file = os.path.join(events_dir,"ebpf_events.jsonl")
        self.outfile = open(events_file,"a",buffering=8192)

        print(f"[+] Writing local log → {events_file}")

        print("[*] Compiling BPF program...")
        self.bpf = BPF(text=bpf_program)
        self.bpf["events"].open_perf_buffer(self.handle_event, page_cnt=64)

        # Flusher
        self.flusher = threading.Thread(target=self.flush_loop,daemon=True)
        self.flusher.start()

        print("[+] eBPF Monitor started.")
  
    def _create_index_template(self):
        mapping = {
            "index_patterns":[f"{self.es_index}*"],
            "template":{
                "mappings":{
                    "properties":{
                        "timestamp_ns":{"type":"long"},
                        "datetime":{"type":"date"},
                        "pid":{"type":"integer"},
                        "ppid":{"type":"integer"},
                        "uid":{"type":"integer"},
                        "comm":{"type":"keyword"},
                        "syscall":{"type":"keyword"},
                        "filename":{"type":"text","fields":{"keyword":{"type":"keyword"}}},
                        "fd":{"type":"long"},
                        "flags":{"type":"long"},
                        "ret":{"type":"long"},
                        "error":{"type":"keyword"},
                        "error_code":{"type":"integer"},
                        "dest_ip":{"type":"keyword"},
                        "dest_ipv6":{"type":"keyword"},
                        "dest_port":{"type":"integer"},
                        "sa_family":{"type":"keyword"},
                        "count":{"type":"long"},
                        "bytes_rw":{"type":"long"},
                    }
                }
            }
        }
        try:
            self.es.indices.put_index_template(name="ebpf-provenance-template",body=mapping)
        except Exception as e:
            print(f"[!] Warning: failed to create ES index template ({e})")

    def format_ipv6(self, arr):
        bytes_list=[]
        for w in arr:
            bytes_list.extend([(w>>24)&255,(w>>16)&255,(w>>8)&255,w&255])
        parts=[]
        for i in range(0,16,2):
            part=(bytes_list[i]<<8)|bytes_list[i+1]
            parts.append(f"{part:x}")
        ipv6=":".join(parts)
        return ipv6.replace(":0:0:0:0:0:0:0:","::")

    def get_error(self, ret):
        if ret>=0: return None, None
        code=-ret
        name=errno.errorcode.get(code,f"UNKNOWN_{code}")
        return name, code

    def debug_print(self, doc):
        """Pretty console printing for debug mode"""
        syscall = doc["syscall"]
        comm = doc["comm"]
        pid = doc["pid"]

        s = json.dumps(doc)
        if len(s) > MAX_DEBUG_LEN:
            s = s[:MAX_DEBUG_LEN] + " ... <truncated>"

        print(f"\n[DEBUG] {datetime.now().strftime('%H:%M:%S')} │ {comm}({pid}) │ {syscall}")
        print("        " + s)

    def handle_event(self, cpu, data, size):
        event = self.bpf["events"].event(data)

        doc = {
            # Use kernel timestamp for ordering; derive wall-clock for readability
            "timestamp_ns": event.timestamp,
            "datetime": datetime.now().astimezone().isoformat(),
            "pid": event.pid,
            "ppid": event.ppid,
            "uid": event.uid,
            "comm": event.comm.decode("utf-8","replace").strip(),
            "syscall": event.syscall.decode("utf-8","replace").strip(),
            "filename": event.filename.decode("utf-8","replace").strip(),
            "fd": event.fd,
            "ret": event.ret,
        }

        # Error info
        if event.ret < 0:
            name, code = self.get_error(event.ret)
            if name:
                doc["error"] = name
                doc["error_code"] = code

        # Write()
        if doc["syscall"] == "write" and event.count > 0:
            doc["count"] = event.count
            doc["bytes_rw"] = event.bytes_rw
            if doc["fd"] == 0:
                doc["fd"] = event.flags

        # connect()
        if doc["syscall"] == "connect":
            if event.sa_family == 2:
                ip = event.dest_ip
                doc["dest_ip"] = f"{(ip>>24)&255}.{(ip>>16)&255}.{(ip>>8)&255}.{ip&255}"
                doc["dest_port"] = event.dest_port
                doc["sa_family"] = "IPv4"
            elif event.sa_family == 10:
                doc["dest_ipv6"] = self.format_ipv6(event.dest_ipv6)
                doc["dest_port"] = event.dest_port
                doc["sa_family"] = "IPv6"

        # -------- DEBUG PRINT ----------
        if DEBUG:
            self.debug_print(doc)

        # -------- Write to file ----------
        self.outfile.write(json.dumps(doc) + "\n")

        # -------- Buffer for ES ----------
        if self.es_enabled:
            with self.lock:
                self.es_buffer.append({
                    "_index": f"{self.es_index}-{datetime.now().strftime('%Y.%m.%d')}",
                    "_source": doc
                })

        self.event_count += 1

    def flush_loop(self):
        while self.running:
            time.sleep(1)
            if not self.es_enabled:
                continue

            with self.lock:
                if not self.es_buffer:
                    continue
                chunk = self.es_buffer[:self.batch_size]
                self.es_buffer = self.es_buffer[self.batch_size:]

            try:
                helpers.bulk(self.es, chunk)
            except Exception as e:
                print(f"[!] ES Bulk Error: {e}")

    def run(self):
        try:
            while True:
                self.bpf.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\n[+] Stopping...")
            self.running = False
            self.flusher.join()
            self.outfile.close()
            print(f"[+] Total events: {self.event_count}")


# Main

def load_config(path):
    with open(path,"r") as f:
        return json.load(f)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="eBPF syscall monitor")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_config = os.path.abspath(os.path.join(script_dir, "..", "conf", "config.json"))

    parser.add_argument("--config", default=default_config, help="Path to config.json")
    parser.add_argument("--debug", action="store_true", help="Enable console debug printing")
    args = parser.parse_args()

    if args.debug:
        DEBUG = True

    config = load_config(args.config)
    EBPFMonitor(config).run()
