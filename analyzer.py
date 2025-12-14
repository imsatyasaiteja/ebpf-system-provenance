#!/usr/bin/env python3
"""
Provenance Graph Analyzer with Advanced Noise Reduction
Implements HOLMES backward slicing and BEEP-style edge grouping and provenance summarization

Key Aspects:
- Entity abstraction (removes instance-specific noise)
- Statistical filtering (frequency-based noise reduction)
- Path factor calculation (prioritizes attacker-influenced flows)
- Enhanced file system filtering
- Process whitelist/blacklist
- Data flow quantity tracking

References:
    BEEP (OSDI 2020) - BEEP: A Scalable Intrusion Detection System
    HOLMES - HOLMES: Real-time APT Detection through Correlation of Suspicious Information Flows
"""

import sys

import argparse
import json
import sys
import os
from collections import defaultdict, Counter
import networkx as nx
from elasticsearch import Elasticsearch
from elasticsearch import ElasticsearchWarning
from datetime import datetime
import re
from networkx.drawing.nx_pydot import write_dot
import warnings

# Silence noisy ES security warnings in demo / local setups
warnings.filterwarnings("ignore", category=ElasticsearchWarning)


# Beep event level compression

TIME_WINDOW_MS = 2000  # 2 seconds for burst detection

def canonicalize_filename(name: str) -> str:
    """
    Canonicalize filenames to detect patterns.
    Examples:
        program1, program2, ... → program<NUM>
        tmp123, tmpABC → tmp<TMP>
    """
    if not name:
        return name
    
    # Extract basename if full path
    basename = name.split('/')[-1]
    
    # Pattern 1: program + digits
    if re.match(r'^program\d+$', basename):
        return "program<NUM>"
    
    # Pattern 2: temp files
    if re.match(r'^tmp\w+$', basename):
        return "tmp<TMP>"
    
    # Pattern 3: General numeric suffix (file1, file2, etc.)
    m = re.match(r'^([A-Za-z_\-]+)\d+$', basename)
    if m:
        return f"{m.group(1)}<NUM>"
    
    return basename


def beep_key(event):
    """
    Create grouping key for BEEP compression.
    Groups by: (parent_pid, syscall, canonical_filename)
    """
    filename = event.get("filename", "")
    canonical = canonicalize_filename(filename)
    
    return (
        event.get("ppid"),
        event.get("syscall"),
        canonical
    )


def beep_compress_events(events, time_window_ms=TIME_WINDOW_MS):
    """
    BEEP event-level compression with correct multi-burst handling.
    
    Groups similar events within time windows to reduce noise.
    Each key can have multiple time-separated bursts.
    
    Args:
        events: List of event dictionaries
        time_window_ms: Time window for grouping (milliseconds)
    
    Returns:
        List of event clusters with metadata
    """
    print(f"[BEEP] Compressing events (window={time_window_ms}ms)...")
    
    # Sort events by timestamp
    events_sorted = sorted(events, key=lambda e: e.get("timestamp_ms", 0))
    
    # Store bursts as a list for each key
    # clusters[key] = [burst1, burst2, ...]
    clusters = defaultdict(list)
    
    for event in events_sorted:
        key = beep_key(event)
        ts = event.get("timestamp_ms", 0)
        
        # Check if we can merge with the last burst for this key
        if clusters[key]:  # Key has existing bursts
            last_burst = clusters[key][-1]
            
            # If within time window, merge into last burst
            if ts - last_burst["end"] <= time_window_ms:
                last_burst["end"] = ts
                last_burst["count"] += 1
                last_burst["events"].append(event)
            else:
                # Start new burst (time gap too large)
                clusters[key].append({
                    "start": ts,
                    "end": ts,
                    "count": 1,
                    "events": [event]
                })
        else:
            # First burst for this key
            clusters[key].append({
                "start": ts,
                "end": ts,
                "count": 1,
                "events": [event]
            })
    
    # Flatten: Convert clusters dict to list
    compressed_events = []
    
    for key, bursts in clusters.items():
        ppid, syscall, canonical_target = key
        
        for burst_idx, burst in enumerate(bursts):
            compressed_events.append({
                # Metadata
                "ppid": ppid,
                "syscall": syscall,
                "canonical_target": canonical_target,
                
                # Burst info
                "count": burst["count"],
                "start_ts": burst["start"],
                "end_ts": burst["end"],
                "burst_id": burst_idx,
                
                # Original events
                "events": burst["events"]
            })
    
    # Statistics
    original_count = len(events)
    compressed_count = len(compressed_events)
    
    if original_count > 0:
        reduction_pct = (1 - compressed_count/original_count) * 100
        print(f"[+] Event compression: {original_count} → {compressed_count} events ({reduction_pct:.1f}% reduction)")
    
    return compressed_events


# Noise reduction compression

# Known benign processes that create noise
BENIGN_PROCESS_PATTERNS = [
    r'^systemd.*',
    r'^dbus.*',
    r'^kworker.*',
    r'^rcu_.*',
    r'^migration.*',
    r'^ksoftirqd.*',
    r'^watchdog.*',
    r'^cpuhp.*',
    r'^kdevtmpfs.*',
    r'^netns.*',
    r'^kthreadd.*',
    r'^irq/.*',
    r'^.*-gvfs.*',
    r'^gnome-.*',
    r'^update-.*',
    r'^cron.*',
]

# File paths that are typically system noise
NOISE_FILE_PATTERNS = [
    r'^/proc/.*',
    r'^/sys/.*',
    r'^/dev/(null|zero|random|urandom|pts/.*)$',
    r'^/tmp/\.X11-unix/.*',
    r'^/run/user/.*',
    r'^(/usr/lib|/lib|/usr/lib64|/lib64).*\.so(\.\d+)*$',
    r'.*\.desktop$',
    r'^/usr/share/(locale|icons|themes|fonts)/.*',
    r'^/usr/lib.*/locale/.*',
    r'^/var/cache/.*',
    r'^/var/lib/dpkg/.*',
    r'^/etc/ld\.so\.cache$',
    r'^/etc/localtime$',
    r'^/usr/include/.*',
    r'.*\.h$',                 # C Headers
    r'.*\.gch$',               # Precompiled headers
    r'/tmp/cc.*\.s$',          # Assembly intermediates
    r'/tmp/cc.*\.o$',          # Object intermediates
    r'/tmp/cc.*\.res$',        # Resource files
    r'/tmp/cc.*\.ld$',         # Linker scripts
    r'/tmp/cc.*\.le$'
]

# Sensitive paths that should NEVER be filtered
SENSITIVE_FILE_PATTERNS = [
    r'.*/secret/.*',
    r'.*/attacker/.*',
    r'.*/ssh/.*',
    r'.*/\.aws/.*',
    r'.*/\.ssh/.*',
]

# HOLMES-specific: Files that trigger alerts
HOLMES_ALERT_PATTERNS = [
    r'.*/secret/.*',
    r'.*/attacker/.*',
    r'.*/\.ssh/.*',
    r'.*/\.aws/.*',
]

def get_base_comm(comm):
    """Extract base command name without path"""
    if comm.startswith('[') and comm.endswith(']'):
        return comm
    base = os.path.basename(comm)
    base = re.split(r'[^a-zA-Z0-9_-]', base)[0]
    return base if base else comm

def is_benign_process(comm):
    """Check if process name matches known benign patterns"""
    for pattern in BENIGN_PROCESS_PATTERNS:
        if re.match(pattern, comm, re.IGNORECASE):
            return True
    return False

def is_noise_file(filepath):
    """Check if file path is system noise"""
    for pattern in SENSITIVE_FILE_PATTERNS:
        if re.search(pattern, filepath):
            return False
    
    for pattern in NOISE_FILE_PATTERNS:
        if re.match(pattern, filepath):
            return True
    return False

def abstract_file_path(filepath):
    """Abstract file paths to remove user-specific details"""
    filepath = re.sub(r'/home/[^/]+/', '/home/*/', filepath)
    filepath = re.sub(r'/tmp/[0-9]+', '/tmp/*', filepath)
    filepath = re.sub(r'/run/user/[0-9]+', '/run/user/*', filepath)
    return filepath

def safe_label(filepath, fallback='unknown_file'):
    """Safely extract label from filepath"""
    if not filepath or not isinstance(filepath, str) or not filepath.strip():
        return fallback
    parts = filepath.rstrip('/').split('/')
    label = parts[-1] if parts else ''
    return label.strip() if label.strip() else fallback

def detect_file_pattern(filenames):
    """Detect common pattern in filenames"""
    if not filenames or len(filenames) < 2:
        return None

    prefix = os.path.commonprefix([str(f) for f in filenames])
    if not prefix:
        return None

    suffixes = []
    for fname in filenames:
        suffix = str(fname)[len(prefix):]
        if suffix.isdigit():
            suffixes.append(int(suffix))

    if len(suffixes) >= 2:
        suffixes.sort()
        if len(suffixes) == (suffixes[-1] - suffixes[0] + 1):
            return f"{prefix}[{suffixes[0]}-{suffixes[-1]}]"
        else:
            return f"{prefix}[×{len(suffixes)}]"

    return None

def sanitize_node_ids(graph):
    """
    Return a copy of the graph with node IDs safe for DOT (no unquoted colons).
    Stores the original ID in the node attrs as 'original_id' for reference.
    """
    mapping = {}
    for node in graph.nodes():
        if isinstance(node, str) and ':' in node:
            safe = node.replace(':', '_')
            # Ensure uniqueness
            suffix = 1
            while safe in mapping.values():
                safe = f"{safe}_{suffix}"
                suffix += 1
            mapping[node] = safe

    if not mapping:
        return graph, mapping

    safe_graph = nx.relabel_nodes(graph, mapping, copy=True)
    for original, safe in mapping.items():
        attrs = safe_graph.nodes[safe]
        attrs['original_id'] = original
        # Preserve existing tooltip but keep original visible if none set
        if 'tooltip' not in attrs or not str(attrs.get('tooltip', '')).strip():
            attrs['tooltip'] = str(original).replace('"', "'")
    return safe_graph, mapping

def escape_dot_value(value):
    """Escape characters that confuse DOT (like colon, quotes, newline)."""
    if not isinstance(value, str):
        return value
    escaped = (
        value.replace('\\', '\\\\')
             .replace('\n', '\\n')
             .replace('"', '\\"')
    )
    return f"\"{escaped}\""

def sanitize_dot_attributes(attrs):
    """Ensure all string attributes are safe for DOT export."""
    for key, val in list(attrs.items()):
        if val is None:
            continue
        if isinstance(val, str):
            attrs[key] = escape_dot_value(val)


class ProvenanceGraph:
    def __init__(self, es_config):
        self.graph = nx.DiGraph()
        self.processes = {} 
        self.process_comm = {}   
        self.pid_start_time = {} 
        self.fd_map = defaultdict(dict) 
        self.es = self._connect_es(es_config)
        self.es_index = es_config.get('es_index', 'ebpf-events')

        # Allow configurable caps for very large queries; default is unlimited
        max_events_cfg = es_config.get('max_events')
        try:
            self.max_events = int(max_events_cfg) if max_events_cfg else None
        except (TypeError, ValueError):
            self.max_events = None
        
        # Enhanced tracking
        self.file_access_count = Counter()
        self.process_file_bytes = defaultdict(lambda: defaultdict(int))
        self.filtered_events = 0
        self.total_events = 0
        
        # BEEP tracking
        self.beep_clusters = []
        self.event_compression_enabled = True

    def _connect_es(self, es_config):
        es_host = es_config.get("es_host", "localhost:9200")
        if not es_host.startswith(('http://', 'https://')):
            es_host = f"https://{es_host}"
        
        es = Elasticsearch(
            [es_host],
            basic_auth=(es_config.get('es_user'), es_config.get('es_password')),
            verify_certs=False, ssl_show_warn=False, 
            request_timeout=30
        )
        if not es.ping():
            raise ConnectionError(f"Failed to connect to ES at {es_host}")
        return es

    def load_events(self, start_time, end_time):
        print(f"[*] Fetching events from {start_time} to {end_time}")
        query = {
            "size": 10000,
            "query": {"range": {"datetime": {"gte": start_time, "lte": end_time}}},
            "sort": [{"timestamp_ns": {"order": "asc"}}]
        }
        try:
            response = self.es.search(index=f"{self.es_index}*", body=query, scroll='2m')
            sid = response['_scroll_id']
            scroll_size = len(response['hits']['hits'])
            events = [hit['_source'] for hit in response['hits']['hits']]
            
            while scroll_size > 0:
                response = self.es.scroll(scroll_id=sid, scroll='2m')
                sid = response['_scroll_id']
                scroll_size = len(response['hits']['hits'])
                events.extend([hit['_source'] for hit in response['hits']['hits']])
                
                if self.max_events and len(events) >= self.max_events:
                    print(f"[!] Max events limit reached ({self.max_events}). Truncating to most recent events.")
                    break 
            
            self.es.clear_scroll(scroll_id=sid)

            if self.max_events and len(events) > self.max_events:
                # Keep the newest events since the scroll is sorted ascending
                events = events[-self.max_events:]
                print(f"[!] Trimmed to last {self.max_events} events for analysis.")

            print(f"[+] Loaded {len(events)} total events.")
            return events
        except Exception as e:
            print(f"[!] ES Query Failed: {e}", file=sys.stderr)
            return []

    def _get_or_create_node(self, node_id, **attrs):
        if not self.graph.has_node(node_id):
            self.graph.add_node(node_id, **attrs)

    def _get_process_node(self, pid, ppid, comm, timestamp_ms):
        if pid not in self.processes:
            proc_node_id = f"proc_{pid}_{timestamp_ms}"
            self.processes[pid] = proc_node_id
            self.pid_start_time[pid] = timestamp_ms
            self.process_comm[pid] = comm
            self._get_or_create_node(
                proc_node_id, 
                label=f"{comm}\n(PID: {pid})", 
                type="process", 
                comm=comm, 
                pid=pid,
                benign=is_benign_process(comm)
            )
            
            if ppid in self.processes:
                parent_node_id = self.processes[ppid]
                self.graph.add_edge(
                    parent_node_id, 
                    proc_node_id, 
                    label="spawned", 
                    time=datetime.fromtimestamp(timestamp_ms/1000).isoformat(),
                    edge_type="control"
                )
        
        proc_node_id = self.processes[pid]
        if self.process_comm.get(pid) != comm:
            self.process_comm[pid] = comm
            self.graph.nodes[proc_node_id]['comm'] = comm
            self.graph.nodes[proc_node_id]['label'] = f"{comm}\n(PID: {pid})"
        return proc_node_id

    def _should_filter_event(self, event):
        """Advanced event filtering"""
        syscall = event['syscall']
        filename = event.get('filename', '')

        if filename and is_noise_file(filename):
            return True

        if syscall in ['openat', 'read'] and filename:
            is_sensitive = any(re.search(p, filename) for p in SENSITIVE_FILE_PATTERNS)
            if not is_sensitive and is_noise_file(filename):
                return True

        return False

    def find_processes_by_pid(self, target_pid):
        """Find all process nodes matching the given PID"""
        found_procs = []
        for node_id, data in self.graph.nodes(data=True):
            if data.get('type') == 'process' and str(data.get('pid')) == str(target_pid):
                found_procs.append(node_id)
        return found_procs

    def build_graph(self, events, enable_filtering=True, enable_event_compression=True):
        """
        Build provenance graph with optional BEEP event-level compression
        
        Args:
            events: List of raw events from Elasticsearch
            enable_filtering: Apply noise filtering
            enable_event_compression: Apply BEEP event compression before graph construction
        """
        print(f"[*] Building provenance graph (filtering={'enabled' if enable_filtering else 'disabled'})...")
        
        self.total_events = len(events)
        self.filtered_events = 0
        self.event_compression_enabled = enable_event_compression
        
        # BEEP STEP 1: Event-level compression (optional)
        if enable_event_compression:
            self.beep_clusters = beep_compress_events(events, TIME_WINDOW_MS)
            print(f"[*] Processing {len(self.beep_clusters)} event clusters...")
        
        # Process events normally (compression info available for reference)
        for event in events:
            # Apply filtering
            if enable_filtering and self._should_filter_event(event):
                self.filtered_events += 1
                continue
            
            pid = str(event['pid'])
            ppid = str(event['ppid'])
            comm = event.get('comm', 'unknown').split('\x00', 1)[0].strip()
            syscall = event['syscall']
            
            if 'timestamp_ns' in event:
                timestamp_ms = event['timestamp_ns'] // 1000000
            else:
                timestamp_ms = event.get('timestamp_ms', 0)
            
            # Update comm name on execve
            if syscall == 'execve' and event.get('filename'):
                new_comm = event['filename'].split('/')[-1]
                if new_comm: 
                    comm = new_comm
            
            proc_node_id = self._get_process_node(pid, ppid, comm, timestamp_ms)

            # Handle different syscalls
            if syscall == 'execve':
                file_node = event.get('filename', '')
                if not file_node or not file_node.strip():
                    continue

                abstract_path = abstract_file_path(file_node)
                self._get_or_create_node(
                    file_node,
                    label=safe_label(file_node, 'exec_file'),
                    type="file",
                    abstract_path=abstract_path
                )
                self.graph.add_edge(
                    proc_node_id,
                    file_node,
                    label="executed",
                    time=event['datetime'],
                    edge_type="control"
                )
            
            elif syscall == 'openat':
                fd = event.get('fd', -1)
                if fd >= 0:
                    file_node = event.get('filename', '')
                    if not file_node or not file_node.strip():
                        continue

                    self.fd_map[pid][fd] = file_node
                    self.file_access_count[file_node] += 1

                    abstract_path = abstract_file_path(file_node)
                    self._get_or_create_node(
                        file_node,
                        label=safe_label(file_node, f'file_fd{fd}'),
                        type="file",
                        abstract_path=abstract_path
                    )
                    self.graph.add_edge(
                        proc_node_id,
                        file_node,
                        label="open",
                        time=event['datetime'],
                        edge_type="data"
                    )
            
            elif syscall == 'read':
                fd = event.get('fd', -1)
                if fd in self.fd_map[pid]:
                    file_node = self.fd_map[pid][fd]
                    ret_bytes = event.get('ret', 0)
                    if ret_bytes > 0:
                        self.process_file_bytes[pid][file_node] += ret_bytes
                    
                    self.graph.add_edge(
                        file_node, 
                        proc_node_id, 
                        label="read", 
                        time=event['datetime'],
                        edge_type="data",
                        bytes=ret_bytes
                    )
            
            elif syscall == 'write':
                fd = event.get('fd', -1)
                if fd in self.fd_map[pid]:
                    file_node = self.fd_map[pid][fd]
                    ret_bytes = event.get('ret', 0)
                    if ret_bytes > 0:
                        self.process_file_bytes[pid][file_node] += ret_bytes
                    
                    self.graph.add_edge(
                        proc_node_id, 
                        file_node, 
                        label="write", 
                        time=event['datetime'],
                        edge_type="data",
                        bytes=ret_bytes
                    )
            
            elif syscall == 'unlinkat':
                file_node = event.get('filename', '')
                if not file_node or not file_node.strip():
                    continue

                abstract_path = abstract_file_path(file_node)
                self._get_or_create_node(
                    file_node,
                    label=safe_label(file_node, 'deleted_file'),
                    type="file",
                    abstract_path=abstract_path
                )
                self.graph.add_edge(
                    proc_node_id,
                    file_node,
                    label="deleted",
                    time=event['datetime'],
                    edge_type="data"
                )
            
            elif syscall == 'connect':
                dest_ip = event.get('dest_ip', 'unknown_ip')
                dest_port = event.get('dest_port', 0)

                if dest_ip in ['127.0.0.1', 'localhost', '::1']:
                    suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999]
                    if dest_port not in suspicious_ports:
                        continue

                net_node_id = f"net_{dest_ip}_{dest_port}"
                net_label = f"Connect:\n{dest_ip}:{dest_port}"

                self._get_or_create_node(
                    net_node_id,
                    label=net_label,
                    type="network",
                    dest_ip=dest_ip,
                    dest_port=dest_port
                )
                self.graph.add_edge(
                    proc_node_id,
                    net_node_id,
                    label="connect",
                    time=event['datetime'],
                    edge_type="network"
                )
        
        filtered_pct = (self.filtered_events / self.total_events * 100) if self.total_events > 0 else 0
        print(f"[+] Graph built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")
        print(f"[+] Filtered {self.filtered_events}/{self.total_events} events ({filtered_pct:.1f}% reduction)")

    def calculate_path_factor(self, source_node, target_node):
        """Calculate path factor between nodes"""
        try:
            paths = list(nx.all_simple_paths(self.graph, source_node, target_node, cutoff=5))
            if not paths:
                return float('inf')
            
            min_cover_size = float('inf')
            for path in paths:
                ancestors = set()
                for node in path:
                    node_ancestors = nx.ancestors(self.graph, node)
                    ancestors.update(node_ancestors)
                
                cover_size = len(ancestors)
                min_cover_size = min(min_cover_size, cover_size)
            
            return min_cover_size
        except:
            return float('inf')

    def find_processes_by_name(self, comm_name):
        """Find all process nodes matching the given command name"""
        found_procs = []
        for node_id, data in self.graph.nodes(data=True):
            if data.get('type') == 'process' and data.get('comm') == comm_name:
                found_procs.append(node_id)
        return found_procs

    def get_attack_subgraph(self, target_nodes, max_depth=5, include_parents=True, include_children=True):
        """Extract focused subgraph around target nodes"""
        if not target_nodes:
            return nx.DiGraph()
            
        print(f"[*] Extracting subgraph for {target_nodes}. Parents={include_parents}, Children={include_children}")
        
        subgraph_nodes = set(target_nodes)
        
        for node in target_nodes:
            if not self.graph.has_node(node): 
                continue
            
            if include_parents:
                ancestors = nx.bfs_tree(self.graph, node, reverse=True, depth_limit=max_depth)
                subgraph_nodes.update(ancestors.nodes())
            
            if include_children:
                descendants = nx.bfs_tree(self.graph, node, reverse=False, depth_limit=max_depth)
                subgraph_nodes.update(descendants.nodes())
        
        subgraph = self.graph.subgraph(subgraph_nodes).copy()
        print(f"[+] Subgraph extracted: {subgraph.number_of_nodes()} nodes")
        return subgraph

    def prune_high_degree_files(self, graph, degree_threshold=5):
        """Remove high-degree file nodes"""
        print(f"[*] Pruning high-degree files (degree > {degree_threshold})...")
        nodes_to_remove = []
        
        for node, attrs in graph.nodes(data=True):
            if attrs.get('type') == 'file':
                total_degree = graph.in_degree(node) + graph.out_degree(node)
                filepath = str(node)
                
                is_sensitive = any(re.search(p, filepath) for p in SENSITIVE_FILE_PATTERNS)
                
                if total_degree > degree_threshold and not is_sensitive:
                    nodes_to_remove.append(node)
        
        if nodes_to_remove:
            print(f"[-] Removing {len(nodes_to_remove)} high-degree files")
            for node in nodes_to_remove[:5]:
                degree = graph.in_degree(node) + graph.out_degree(node)
                print(f"    - {node} (degree={degree})")
            graph.remove_nodes_from(nodes_to_remove)
        
        return graph

    def remove_benign_only_subgraphs(self, graph):
        """Remove disconnected subgraphs with only benign processes"""
        print("[*] Removing benign-only subgraphs...")
        
        if graph.number_of_nodes() == 0:
            return graph
        
        undirected = graph.to_undirected()
        components = list(nx.connected_components(undirected))
        
        nodes_to_remove = []
        for component in components:
            has_malicious = False
            for node in component:
                attrs = graph.nodes[node]
                if attrs.get('type') == 'process' and not attrs.get('benign', False):
                    has_malicious = True
                    break
                if attrs.get('type') == 'network':
                    has_malicious = True
                    break
            
            if not has_malicious and len(component) < 10:
                nodes_to_remove.extend(component)
        
        if nodes_to_remove:
            print(f"[-] Removing {len(nodes_to_remove)} nodes from benign-only subgraphs")
            graph.remove_nodes_from(nodes_to_remove)
        
        return graph

    def remove_isolated_nodes(self, graph):
        """Remove nodes with no connections"""
        isolates = list(nx.isolates(graph))
        if isolates:
            print(f"[*] Removing {len(isolates)} isolated nodes")
            graph.remove_nodes_from(isolates)
        return graph

    def beep_edge_grouping(self, graph, time_window_ms=2000, min_group_size=3):
        """
        BEEP-style graph-level edge grouping.
        Collapses repetitive edges into abstract nodes.
        """
        print(f"[*] Applying BEEP edge grouping (window={time_window_ms}ms, min_size={min_group_size})...")

        edge_groups = defaultdict(list)

        for u, v, data in list(graph.edges(data=True)):
            source_node = u
            edge_label = data.get('label', '')
            target_node = v
            target_type = graph.nodes[v].get('type', 'unknown')
            time_str = data.get('time', '')

            try:
                if isinstance(time_str, str) and time_str:
                    event_time = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
                    timestamp_ms = int(event_time.timestamp() * 1000)
                else:
                    timestamp_ms = 0
            except:
                timestamp_ms = 0

            # Abstract target for pattern detection
            if target_type == 'process':
                comm = graph.nodes[v].get('comm', '')
                target_abstract = re.sub(r'\d+', '', comm)
            elif target_type == 'file':
                filename = str(target_node).split('/')[-1]
                target_abstract = canonicalize_filename(filename)
            else:
                target_abstract = target_type

            group_key = (source_node, edge_label, target_type, target_abstract)

            edge_groups[group_key].append({
                'source': u,
                'target': v,
                'data': data,
                'timestamp': timestamp_ms
            })

        groups_to_collapse = []

        for group_key, edges in edge_groups.items():
            if len(edges) < min_group_size:
                continue

            edges_sorted = sorted(edges, key=lambda x: x['timestamp'])

            if edges_sorted[-1]['timestamp'] > 0 and edges_sorted[0]['timestamp'] > 0:
                time_span = edges_sorted[-1]['timestamp'] - edges_sorted[0]['timestamp']
                if time_span > time_window_ms:
                    continue

            source_node, edge_label, target_type, target_abstract = group_key
            groups_to_collapse.append({
                'key': group_key,
                'edges': edges_sorted,
                'count': len(edges_sorted)
            })

        if not groups_to_collapse:
            print(f"[+] No edge groups found (nothing to collapse)")
            return graph

        collapsed_count = 0

        for group_info in groups_to_collapse:
            source_node, edge_label, target_type, target_abstract = group_info['key']
            edges = group_info['edges']
            count = group_info['count']

            target_nodes = [e['target'] for e in edges]

            target_labels = []
            for tgt in target_nodes:
                if target_type == 'file':
                    label = safe_label(tgt)
                elif target_type == 'process':
                    label = graph.nodes[tgt].get('comm', safe_label(tgt))
                else:
                    label = str(tgt)
                target_labels.append(label)

            pattern = detect_file_pattern(target_labels)
            if pattern:
                abstract_label = f"{pattern}"
            elif target_abstract and target_abstract != "":
                abstract_label = f"{target_abstract} [×{count}]"
            else:
                abstract_label = f"{target_labels[0]}... [×{count}]"

            abstract_node_id = f"BEEP_GROUP_{source_node}_{edge_label}_{target_type}_{collapsed_count}"

            graph.add_node(
                abstract_node_id,
                label=abstract_label,
                type=f"beep_{target_type}",
                beep_group=True,
                group_size=count,
                edge_type=edge_label,
                original_targets=target_labels,
                shape='box3d',
                style='filled,bold',
                fillcolor='#FFD700'
            )

            first_time = edges[0]['data'].get('time', 'N/A')
            last_time = edges[-1]['data'].get('time', 'N/A')

            graph.add_edge(
                source_node,
                abstract_node_id,
                label=f"{edge_label} [×{count}]",
                time=first_time,
                time_range=f"{first_time} to {last_time}",
                edge_type='beep_aggregated',
                group_size=count
            )

            for edge in edges:
                target = edge['target']

                if graph.has_edge(edge['source'], target):
                    graph.remove_edge(edge['source'], target)

                if graph.has_node(target):
                    if graph.in_degree(target) == 0 and graph.out_degree(target) == 0:
                        graph.remove_node(target)

            collapsed_count += 1

        print(f"[+] BEEP: Collapsed {collapsed_count} edge groups")
        print(f"[+] Graph after BEEP: {graph.number_of_nodes()} nodes, {graph.number_of_edges()} edges")

        return graph

    def compress_structural_nodes(self, graph):
        """ProvGRP-style Structural Compression"""
        print("[*] Applying Structural Node Compression (ProvGRP)...")
        
        changed = True
        iteration = 0
        
        while changed and iteration < 5:
            changed = False
            iteration += 1
            
            signatures = defaultdict(list)
            
            nodes_list = list(graph.nodes(data=True))
            for node, attrs in nodes_list:
                if attrs.get('beep_group'): 
                    continue 
                
                in_sig = []
                for u, _, data in graph.in_edges(node, data=True):
                    in_sig.append((u, data.get('label', '')))
                in_sig.sort()
                
                out_sig = []
                for _, v, data in graph.out_edges(node, data=True):
                    out_sig.append((data.get('label', ''), v))
                out_sig.sort()
                
                identity = attrs.get('comm') if attrs.get('type') == 'process' else safe_label(str(node))
                identity_pattern = re.sub(r'\d+', '', identity)
                
                sig = (attrs.get('type'), tuple(in_sig), tuple(out_sig), identity_pattern)
                signatures[sig].append(node)
            
            for sig, nodes in signatures.items():
                if len(nodes) < 2:
                    continue
                    
                keep_node = nodes[0]
                remove_nodes = nodes[1:]
                
                count = len(nodes)
                old_label = graph.nodes[keep_node].get('label', str(keep_node))
                
                node_names = [str(n) for n in nodes]
                pattern_name = detect_file_pattern(node_names)
                
                if pattern_name:
                    new_label = f"{pattern_name}"
                else:
                    clean_label = old_label.split('\n')[0]
                    new_label = f"{clean_label} [×{count}]"
                
                graph.nodes[keep_node]['label'] = new_label
                graph.nodes[keep_node]['count'] = count
                graph.nodes[keep_node]['shape'] = 'folder'
                
                graph.remove_nodes_from(remove_nodes)
                changed = True
                
        print(f"[+] Structural compression finished after {iteration} iterations")
        return graph

    def holmes_backward_slice(self, graph, enable_forward=True):
        """HOLMES-style backward slicing"""
        print(f"[*] Applying HOLMES backward slicing (Enhanced)...")

        if graph.number_of_nodes() == 0:
            return graph

        alert_nodes = set()

        for node, attrs in graph.nodes(data=True):
            node_type = attrs.get('type', '')
            
            if node_type == 'process':
                for successor in graph.successors(node):
                    edge_data = graph.get_edge_data(node, successor)
                    if isinstance(edge_data, dict): 
                        labels = [d.get('label') for d in edge_data.values()] if 0 in edge_data else [edge_data.get('label')]
                        
                        if 'deleted' in labels or 'unlink' in str(labels):
                            alert_nodes.add(node)
                            print(f"[!] Alert: {attrs.get('comm', node)} deleted a file (Cleanup detection)")
            
            if node_type == 'file':
                filepath = str(node)
                for pattern in HOLMES_ALERT_PATTERNS:
                    if re.search(pattern, filepath):
                        for pred in graph.predecessors(node):
                            if graph.nodes[pred].get('type') == 'process':
                                alert_nodes.add(pred)
                                print(f"[!] Alert: {graph.nodes[pred].get('comm', pred)} accessed {filepath}")

            if node_type == 'network':
                for pred in graph.predecessors(node):
                    if graph.nodes[pred].get('type') == 'process':
                        comm = graph.nodes[pred].get('comm', '')
                        if comm not in ['nginx', 'apache2', 'httpd']:
                            alert_nodes.add(pred)
                            print(f"[!] Alert: {comm} made network connection")

        if not alert_nodes:
            print(f"[+] No sensitive operations detected, keeping full graph")
            return graph

        print(f"[+] Found {len(alert_nodes)} alert nodes")

        causal_ancestors = set()
        for alert in alert_nodes:
            try:
                ancestors = nx.ancestors(graph, alert)
                causal_ancestors.update(ancestors)
            except nx.NetworkXError:
                pass

        print(f"[+] Backward slice: {len(causal_ancestors)} ancestor nodes")

        consequences = set()
        if enable_forward:
            for alert in alert_nodes:
                try:
                    descendants = nx.descendants(graph, alert)
                    consequences.update(descendants)
                except nx.NetworkXError:
                    pass
            print(f"[+] Forward slice: {len(consequences)} descendant nodes")

        siblings = set()
        for ancestor in causal_ancestors:
            if graph.nodes[ancestor].get('type') == 'process':
                children = graph.successors(ancestor)
                siblings.update(children)
        
        print(f"[+] Sibling expansion: Added {len(siblings)} context nodes")

        keep_nodes = alert_nodes | causal_ancestors | consequences | siblings

        for node, attrs in graph.nodes(data=True):
            node_type = attrs.get('type', '')
            if node_type == 'file':
                filepath = str(node)
                for pattern in HOLMES_ALERT_PATTERNS:
                    if re.search(pattern, filepath):
                        keep_nodes.add(node)
            elif node_type == 'network':
                keep_nodes.add(node)

        all_nodes = set(graph.nodes())
        remove_nodes = all_nodes - keep_nodes

        if remove_nodes:
            print(f"[-] HOLMES: Removing {len(remove_nodes)} non-causal nodes")
            graph.remove_nodes_from(remove_nodes)

        return graph

    def filter_temporal_window(self, graph, attack_start_time, window_hours=1):
        """Remove processes outside temporal window"""
        print(f"[*] Filtering processes outside {window_hours}h window from attack start...")

        from datetime import datetime, timedelta

        try:
            if isinstance(attack_start_time, str):
                attack_dt = datetime.fromisoformat(attack_start_time.replace('Z', '+00:00'))
            else:
                attack_dt = attack_start_time

            window_start = attack_dt - timedelta(hours=window_hours)
            window_start_ms = int(window_start.timestamp() * 1000)

            nodes_to_remove = []

            for node, attrs in graph.nodes(data=True):
                if attrs.get('type') == 'process':
                    pid = attrs.get('pid')

                    if pid and str(pid) in self.pid_start_time:
                        start_time_ms = self.pid_start_time[str(pid)]

                        if start_time_ms < window_start_ms:
                            if attrs.get('benign', False):
                                nodes_to_remove.append(node)

            if nodes_to_remove:
                print(f"[-] Removing {len(nodes_to_remove)} processes that started before attack window")
                graph.remove_nodes_from(nodes_to_remove)

            return graph

        except Exception as e:
            print(f"[!] Temporal filtering failed: {e}")
            return graph

    def export_text_summary(self, graph, filename):
        """Export human-readable summary"""
        if not graph: 
            return
        
        print(f"[*] Exporting text summary to {filename}...")
        try:
            edges = sorted(graph.edges(data=True), key=lambda x: x[2].get('time', ''))
            with open(filename, 'w') as f:
                f.write("=== ATTACK PROVENANCE ANALYSIS ===\n\n")
                f.write(f"Total Nodes: {graph.number_of_nodes()}\n")
                f.write(f"Total Edges: {graph.number_of_edges()}\n\n")
                
                proc_count = sum(1 for _, d in graph.nodes(data=True) if d.get('type') == 'process')
                file_count = sum(1 for _, d in graph.nodes(data=True) if d.get('type') == 'file')
                net_count = sum(1 for _, d in graph.nodes(data=True) if d.get('type') == 'network')
                
                f.write(f"Processes: {proc_count}\n")
                f.write(f"Files: {file_count}\n")
                f.write(f"Network: {net_count}\n\n")
                
                # Add BEEP statistics if available
                if self.beep_clusters:
                    f.write(f"BEEP Event Clusters: {len(self.beep_clusters)}\n")
                    burst_count = sum(1 for c in self.beep_clusters if c['count'] > 1)
                    f.write(f"Multi-event Bursts: {burst_count}\n\n")
                
                f.write("=== CHRONOLOGICAL EVENTS ===\n\n")
                for u, v, data in edges:
                    src = graph.nodes[u].get('label', u).replace('\n', ' ')
                    dst = graph.nodes[v].get('label', v).replace('\n', ' ')
                    edge_label = data.get('label', '')
                    timestamp = data.get('time', 'N/A')
                    
                    f.write(f"[{timestamp}] {src} --[{edge_label}]--> {dst}\n")
            
            print(f"[+] Text summary saved")
        except Exception as e:
            print(f"[!] Text export failed: {e}")

    def export_to_dot(self, graph, filename, focus_nodes=None):
        """Export graph to DOT format with visual styling"""
        if not graph: 
            return
        
        print(f"[*] Exporting to DOT format...")

        # Sanitize node IDs for DOT (colons require quoting)
        graph, id_mapping = sanitize_node_ids(graph)
        # Remap focus nodes if provided
        if focus_nodes and id_mapping:
            focus_nodes = [id_mapping.get(n, n) for n in focus_nodes]

        for node_id in graph.nodes():
            data = graph.nodes[node_id]

            if 'label' not in data or not str(data.get('label', '')).strip():
                if data.get('type') == 'file':
                    data['label'] = safe_label(str(node_id), 'unnamed_file')
                else:
                    data['label'] = str(node_id) if str(node_id).strip() else 'unnamed_node'
            
            if data.get('beep_group', False):
                pass
            elif data.get('type') == 'process':
                data['shape'] = 'box'
                data['style'] = 'filled,rounded'
                if data.get('benign', False):
                    data['fillcolor'] = '#AAAAAA'
                else:
                    data['fillcolor'] = '#40A8D1'
            elif data.get('type') == 'network':
                data['shape'] = 'diamond'
                data['style'] = 'filled'
                data['fillcolor'] = '#FF69B4'
            elif data.get('type') == 'file':
                data['shape'] = 'note'
                data['style'] = 'filled'
                filepath = str(node_id)
                if any(re.search(p, filepath) for p in SENSITIVE_FILE_PATTERNS):
                    data['fillcolor'] = '#D14040'
                elif '/tmp/' in filepath or '/Downloads/' in filepath:
                    data['fillcolor'] = '#D18C40'
                else:
                    data['fillcolor'] = '#CCCCCC'

            if focus_nodes and node_id in focus_nodes:
                data['penwidth'] = '4.0'
                data['color'] = 'red'
            else:
                data['penwidth'] = '1.0'
                data['color'] = 'black'
            
            data['tooltip'] = str(data).replace('"', "'")
            sanitize_dot_attributes(data)
        
        for _, _, edge_attrs in graph.edges(data=True):
            sanitize_dot_attributes(edge_attrs)
        
        graph.graph['graph'] = {'rankdir': 'LR'}
        
        try:
            write_dot(graph, filename)
            print(f"[+] DOT file saved: {filename}")
        except Exception as e:
            print(f"[!] DOT export failed: {e}", file=sys.stderr)
            raise


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Provenance Graph Analyzer with Noise Reduction"
    )
    parser.add_argument("--comm", type=str, help="Target process name")
    parser.add_argument("--pid", type=str, help="Target process PID")
    parser.add_argument("--start", type=str, required=True, help="Start time (ISO format)")
    parser.add_argument("--end", type=str, required=True, help="End time (ISO format)")
    parser.add_argument("--depth", type=int, default=5, help="Max graph depth")
    parser.add_argument("--out", type=str, default="provenance_attack_0.dot", help="Output DOT file")
    parser.add_argument("--text-out", type=str, default="attack_summary.txt", help="Text summary file")
    
    parser.add_argument("--no-parents", action="store_true", help="Disable ancestor tracing")
    parser.add_argument("--no-children", action="store_true", help="Disable descendant tracing")
    parser.add_argument("--prune", action="store_true", help="Enable high-degree pruning")
    parser.add_argument("--no-filter", action="store_true", help="Disable event filtering")
    parser.add_argument("--degree-threshold", type=int, default=5, help="Degree threshold for pruning")
    parser.add_argument("--beep", action="store_true", help="Enable BEEP edge grouping")
    parser.add_argument("--beep-window", type=int, default=2000, help="BEEP time window in ms")
    parser.add_argument("--beep-threshold", type=int, default=3, help="BEEP minimum group size")
    parser.add_argument("--no-event-compression", action="store_true", help="Disable BEEP event-level compression")
    parser.add_argument("--holmes", action="store_true", help="Enable HOLMES backward slicing")
    parser.add_argument("--both", action="store_true", help="Uses both HOLMES backward slicing and BEEP edge grouping")
    parser.add_argument("--holmes-forward", action="store_true", default=True, help="HOLMES: trace forward from alerts")
    parser.add_argument("--cli-only", action="store_true", help="CLI mode: display summary in terminal")
    
    args = parser.parse_args()

    try:
        with open('./conf/config.json', 'r') as f:
            config = json.load(f)
    except FileNotFoundError:
        print("[!] Config file not found", file=sys.stderr)
        sys.exit(1)

    output_dir = config.get('output_dir', '.')
    os.makedirs(output_dir, exist_ok=True)

    for f in [args.out, args.out.replace('.dot', '.png'), args.text_out]:
        if os.path.exists(f):
            try:
                os.remove(f)
            except OSError:
                pass

    try:
        analyzer = ProvenanceGraph(config)
        events = analyzer.load_events(args.start, args.end)
        if not events: 
            print("[!] No events found", file=sys.stderr)
            sys.exit(1)
        
        # Build with optional event compression
        analyzer.build_graph(
            events, 
            enable_filtering=not args.no_filter,
            enable_event_compression=not args.no_event_compression
        )

        target_procs = []
        if args.pid:
            print(f"[*] Searching for PID: {args.pid}")
            target_procs = analyzer.find_processes_by_pid(args.pid)
            if not target_procs:
                print(f"[!] No process found with PID '{args.pid}'")
                sys.exit(1)
        elif args.comm:
            print(f"[*] Searching for Comm: {args.comm}")
            target_procs = analyzer.find_processes_by_name(args.comm)
            if not target_procs:
                print(f"[!] No process found named '{args.comm}'")
                sys.exit(1)
        else:
            print("[!] You must specify either --comm or --pid", file=sys.stderr)
            sys.exit(1)
        
        print(f"[+] Found {len(target_procs)} matching processes. Using the first one.")
        
        attack_subgraph = analyzer.get_attack_subgraph(
            [target_procs[0]], 
            max_depth=args.depth,
            include_parents=not args.no_parents,
            include_children=not args.no_children
        )
        
        attack_subgraph = analyzer.filter_temporal_window(
            attack_subgraph,
            args.start,
            window_hours=1
        )

        if args.holmes:
            attack_subgraph = analyzer.holmes_backward_slice(
                attack_subgraph,
                enable_forward=args.holmes_forward
            )
            attack_subgraph = analyzer.compress_structural_nodes(attack_subgraph)

        if args.beep:
            attack_subgraph = analyzer.beep_edge_grouping(
                attack_subgraph,
                time_window_ms=args.beep_window,
                min_group_size=args.beep_threshold
            )

        if args.both:
            attack_subgraph = analyzer.holmes_backward_slice(
                attack_subgraph,
                enable_forward=args.holmes_forward
            )
            attack_subgraph = analyzer.compress_structural_nodes(attack_subgraph)
            attack_subgraph = analyzer.beep_edge_grouping(
                attack_subgraph,
                time_window_ms=args.beep_window,
                min_group_size=args.beep_threshold
            )

        if args.prune:
            attack_subgraph = analyzer.prune_high_degree_files(
                attack_subgraph,
                degree_threshold=args.degree_threshold
            )

        attack_subgraph = analyzer.remove_benign_only_subgraphs(attack_subgraph)
        attack_subgraph = analyzer.remove_isolated_nodes(attack_subgraph)
        
        if attack_subgraph.number_of_nodes() > 0:
            analyzer.export_to_dot(attack_subgraph, args.out, focus_nodes=[target_procs[0]])
            analyzer.export_text_summary(attack_subgraph, args.text_out)
            print(f"\n[✓] Analysis complete!")
            print(f"[✓] Final graph: {attack_subgraph.number_of_nodes()} nodes, {attack_subgraph.number_of_edges()} edges")

            if args.cli_only:
                print("\n" + "="*80)
                print("ATTACK SUMMARY")
                print("="*80)
                with open(args.text_out, 'r') as f:
                    summary_text = f.read()
                    print(summary_text)
                print("="*80)
                print(f"\n[i] Graph file: {args.out}")
                print(f"[i] To visualize: dot -Tpng {args.out} -o graph.png && xdg-open graph.png")
        else:
            print("[!] No attack graph generated (all nodes filtered)")
            sys.exit(1)
        
    except Exception as e:
        print(f"[!] Fatal error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
