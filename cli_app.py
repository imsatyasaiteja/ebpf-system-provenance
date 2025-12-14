#!/usr/bin/env python3
"""
Terminal CLI for eBPF Forensic Monitor

This provides a guided, menu-driven interface that provides the key features of our eBPF Forensic Monitor:
  - Raw log browsing with filters and pagination
  - Provenance graph generation
  - Syscall / process statistics
  - AI-powered attack analysis chat (Ollama Model)
  - Log cleanup and Elasticsearch trimming
"""

import sys

import os
import json
import time
import subprocess
from datetime import datetime, timedelta, timezone

import urllib3
import requests
from elasticsearch import Elasticsearch

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_PATH = "./conf/config.json"
ANALYZER_SCRIPT_PATH = "./analyzer.py"
LOCAL_TZ = datetime.now().astimezone().tzinfo or timezone.utc
OLLAMA_DEFAULT_HOST = os.environ.get("OLLAMA_HOST", "http://192.168.56.1:11434")


# Shared helpers (adapted from app_streamlit.py, but without Streamlit deps)

def load_config():
    if not os.path.exists(CONFIG_PATH):
        print(f"[!] Config file not found at {CONFIG_PATH}", file=sys.stderr)
        sys.exit(1)
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)


def connect_elasticsearch(config):
    es_host = config.get("es_host", "localhost:9200")
    es_user = config.get("es_user", None)
    es_pass = config.get("es_password", None)

    if not es_host.startswith(("http://", "https://")):
        es_host = f"http://{es_host}"

    try:
        es = Elasticsearch(
            es_host,
            basic_auth=(es_user, es_pass),
            verify_certs=False,
            request_timeout=10,
        )
        if not es.ping():
            print("[!] Cannot connect to Elasticsearch", file=sys.stderr)
            return None
        return es
    except Exception as e:
        print(f"[!] Elasticsearch connection error: {e}", file=sys.stderr)
        return None


def get_index_names(start_date, end_date, base_name):
    indices = []
    current = start_date
    while current <= end_date:
        index_name = f"{base_name}-{current.strftime('%Y.%m.%d')}"
        indices.append(index_name)
        current += timedelta(days=1)
    return indices


def get_total_event_count(
    es,
    indices,
    start_datetime,
    end_datetime,
    syscall_filter=None,
    comm_filter=None,
    pid_filter=None,
    ppid_filter=None,
    filename_filter=None,
):
    """Get total count of events matching the filters."""
    if es is None:
        return 0

    must_conditions = [
        {
            "range": {
                "datetime": {
                    "gte": start_datetime.isoformat(),
                    "lte": end_datetime.isoformat(),
                }
            }
        }
    ]

    if syscall_filter:
        must_conditions.append({"term": {"syscall": syscall_filter}})
    if comm_filter:
        must_conditions.append({"term": {"comm": comm_filter}})
    if pid_filter:
        must_conditions.append({"term": {"pid": pid_filter}})
    if ppid_filter:
        must_conditions.append({"term": {"ppid": ppid_filter}})
    if filename_filter:
        wildcard_value = (
            filename_filter
            if any(ch in filename_filter for ch in ["*", "?"])
            else f"*{filename_filter}*"
        )
        must_conditions.append(
            {"wildcard": {"filename.keyword": {"value": wildcard_value}}}
        )

    count_query = {"query": {"bool": {"must": must_conditions}}}
    total_count = 0
    for index in indices:
        try:
            if not es.indices.exists(index=index):
                continue
            response = es.count(index=index, body=count_query)
            total_count += response["count"]
        except Exception:
            pass

    return total_count


def fetch_events(
    es,
    indices,
    start_datetime,
    end_datetime,
    syscall_filter=None,
    comm_filter=None,
    pid_filter=None,
    ppid_filter=None,
    filename_filter=None,
    page=1,
    page_size=1000,
):
    if es is None:
        return []

    must_conditions = [
        {
            "range": {
                "datetime": {
                    "gte": start_datetime.isoformat(),
                    "lte": end_datetime.isoformat(),
                }
            }
        }
    ]

    if syscall_filter:
        must_conditions.append({"term": {"syscall": syscall_filter}})
    if comm_filter:
        must_conditions.append({"term": {"comm": comm_filter}})
    if pid_filter:
        must_conditions.append({"term": {"pid": pid_filter}})
    if ppid_filter:
        must_conditions.append({"term": {"ppid": ppid_filter}})
    if filename_filter:
        wildcard_value = (
            filename_filter
            if any(ch in filename_filter for ch in ["*", "?"])
            else f"*{filename_filter}*"
        )
        must_conditions.append(
            {"wildcard": {"filename.keyword": {"value": wildcard_value}}}
        )

    query = {
        "query": {"bool": {"must": must_conditions}},
        "sort": [{"datetime": {"order": "desc"}}],
        "from": (page - 1) * page_size,
        "size": page_size,
    }

    all_events = []
    for index in indices:
        try:
            if not es.indices.exists(index=index):
                continue
            response = es.search(index=index, body=query)
            for hit in response["hits"]["hits"]:
                all_events.append(hit["_source"])
        except Exception:
            pass

    return all_events


def compute_time_delta(amount, unit):
    """Convert unit selection into timedelta."""
    unit = unit.lower()
    if unit.startswith("hour"):
        return timedelta(hours=amount)
    if unit.startswith("day"):
        return timedelta(days=amount)
    if unit.startswith("month"):
        return timedelta(days=30 * amount)
    if unit.startswith("year"):
        return timedelta(days=365 * amount)
    return timedelta(hours=amount)


def parse_event_datetime(dt_value):
    if not dt_value:
        return None
    try:
        parsed = datetime.fromisoformat(str(dt_value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=LOCAL_TZ)
        return parsed
    except ValueError:
        return None


def prune_event_logs(events_dir, cutoff_dt):
    """Trim ebpf_events.jsonl to only include events newer than cutoff."""
    log_file = os.path.join(events_dir, "ebpf_events.jsonl")
    if not os.path.exists(log_file):
        return 0, 0, f"Log file not found at {log_file}"

    total = 0
    kept = 0
    retained_lines = []

    with open(log_file, "r") as infile:
        for line in infile:
            stripped = line.strip()
            if not stripped:
                continue
            total += 1
            keep_line = True
            try:
                event = json.loads(stripped)
                event_dt = parse_event_datetime(event.get("datetime"))
                if event_dt and event_dt < cutoff_dt:
                    keep_line = False
            except json.JSONDecodeError:
                keep_line = True

            if keep_line:
                retained_lines.append(line if line.endswith("\n") else line + "\n")
                kept += 1

    with open(log_file, "w") as outfile:
        outfile.writelines(retained_lines)

    return total, kept, None


def delete_old_events_from_es(es, index_base, cutoff_dt):
    """Delete Elasticsearch documents older than cutoff."""
    if es is None:
        return 0, "Elasticsearch client unavailable."

    cutoff_iso = cutoff_dt.isoformat()
    query = {"query": {"range": {"datetime": {"lt": cutoff_iso}}}}
    index_pattern = f"{index_base}-*"

    try:
        response = es.delete_by_query(
            index=index_pattern,
            body=query,
            conflicts="proceed",
            refresh=True,
            wait_for_completion=True,
            ignore_unavailable=True,
        )
        deleted = response.get("deleted", 0)
        return deleted, None
    except Exception as e:
        return 0, f"Elasticsearch cleanup failed: {e}"


def parse_analyzer_stats(stdout_text):
    """Parse statistics from analyzer output."""
    import re

    stats = {
        "events_loaded": 0,
        "events_filtered": 0,
        "filter_percentage": 0,
        "nodes": 0,
        "edges": 0,
    }

    for line in stdout_text.split("\n"):
        if "Loaded" in line and "events" in line:
            match = re.search(r"Loaded (\d+)", line)
            if match:
                stats["events_loaded"] = int(match.group(1))

        if "Filtered" in line and "/" in line:
            match = re.search(
                r"Filtered (\d+)/(\d+) events \((\d+\.?\d*)%", line
            )
            if match:
                stats["events_filtered"] = int(match.group(1))
                stats["filter_percentage"] = float(match.group(3))

        if "Graph built:" in line:
            match = re.search(r"(\d+) nodes, (\d+) edges", line)
            if match:
                stats["nodes"] = int(match.group(1))
                stats["edges"] = int(match.group(2))

        if "Final graph:" in line:
            match = re.search(r"(\d+) nodes, (\d+) edges", line)
            if match:
                stats["nodes"] = int(match.group(1))
                stats["edges"] = int(match.group(2))

    return stats


def query_ollama(prompt, model="llama3.2", host="http://192.168.56.1:11434"):
    """Send a query to Ollama and get response."""
    try:
        payload = {"model": model, "prompt": prompt, "stream": False}

        response = requests.post(
            f"{host}/api/generate",
            json=payload,
            timeout=60,
        )

        if response.status_code == 404:
            try:
                error_detail = response.json()
            except Exception:
                error_detail = response.text
            return (
                "Error 404: API endpoint not found\n\n"
                f"URL: {response.url}\nResponse: {error_detail}\n\n"
                "Troubleshooting:\n"
                "  1. Verify Ollama is running: `ollama serve`\n"
                "  2. Check if model exists: `ollama list`\n"
                f"  3. Pull the model if needed: `ollama pull {model}`\n"
            )

        response.raise_for_status()
        result = response.json()
        return result.get("response", "No response from model")

    except requests.exceptions.HTTPError as e:
        try:
            error_body = e.response.json()
        except Exception:
            error_body = e.response.text
        return f"HTTP Error {e.response.status_code}: {str(e)}\nResponse: {error_body}"
    except requests.exceptions.ConnectionError:
        return (
            f"Cannot connect to Ollama at {host}. "
            "Make sure Ollama is running (try `ollama serve`)."
        )
    except requests.exceptions.Timeout:
        return "Request to Ollama timed out (model may be too slow or prompt too long)."
    except Exception as e:
        return f"Unexpected error: {type(e).__name__}: {str(e)}"


def check_ollama_connection(host="http://192.168.56.1:11434"):
    """Check if Ollama is running and list available models."""
    try:
        response = requests.get(f"{host}/api/tags", timeout=5)
        response.raise_for_status()
        models = response.json().get("models", [])
        model_names = [m.get("name", "") for m in models]
        simplified = list(set([m.split(":")[0] for m in model_names]))
        return True, model_names, simplified
    except Exception:
        return False, [], []


# Interactive helpers

def prompt_time_range():
    """Prompt user for a time range, similar to UI presets."""
    print("\n[ Time Range Selection ]")
    print("  1) Last 1 hour")
    print("  2) Last 24 hours")
    print("  3) Today")
    print("  4) Custom (enter start/end)")

    choice = input("Select option [1-4] (default 1): ").strip() or "1"
    local_now = datetime.now(LOCAL_TZ)

    if choice == "2":
        end_dt = local_now
        start_dt = end_dt - timedelta(hours=24)
    elif choice == "3":
        end_dt = local_now
        start_dt = local_now.replace(
            hour=0, minute=0, second=0, microsecond=0
        )
    elif choice == "4":
        fmt = "%Y-%m-%d %H:%M"
        print(
            "Enter timestamps in local time "
            f"({LOCAL_TZ}) using format: {fmt}"
        )
        start_str = input("  Start (e.g., 2025-01-01 10:00): ").strip()
        end_str = input("  End   (e.g., 2025-01-01 12:00): ").strip()
        try:
            start_dt = datetime.strptime(start_str, fmt).replace(
                tzinfo=LOCAL_TZ
            )
            end_dt = datetime.strptime(end_str, fmt).replace(
                tzinfo=LOCAL_TZ
            )
        except ValueError:
            print("[!] Invalid datetime format, falling back to last 1 hour")
            end_dt = local_now
            start_dt = end_dt - timedelta(hours=1)
    else:
        end_dt = local_now
        start_dt = end_dt - timedelta(hours=1)

    if start_dt >= end_dt:
        print("[!] Start time must be before end time, adjusting to last 1 hour.")
        end_dt = local_now
        start_dt = end_dt - timedelta(hours=1)

    return start_dt, end_dt


def prompt_filters():
    """Prompt user for optional log filters."""
    print("\n[ Optional Filters ] - leave blank to skip")
    syscall = input("  Syscall (e.g., openat): ").strip() or None
    comm = input("  Command/comm (e.g., bash): ").strip() or None
    pid = input("  PID (e.g., 10466): ").strip()
    ppid = input("  PPID (e.g., 28406): ").strip()
    filename = input("  Filename contains/wildcard (e.g., secret.txt or *secret*): ").strip() or None

    pid_int = int(pid) if pid.isdigit() else None
    ppid_int = int(ppid) if ppid.isdigit() else None

    return syscall, comm, pid_int, ppid_int, filename


# Menu actions

def action_view_logs(es, index_base):
    if es is None:
        print("[!] Elasticsearch is not connected. Cannot fetch logs.")
        return

    start_dt, end_dt = prompt_time_range()
    indices = get_index_names(start_dt.date(), end_dt.date(), index_base)
    syscall, comm, pid, ppid, filename = prompt_filters()

    total = get_total_event_count(
        es,
        indices,
        start_dt,
        end_dt,
        syscall_filter=syscall,
        comm_filter=comm,
        pid_filter=pid,
        ppid_filter=ppid,
        filename_filter=filename,
    )

    if total == 0:
        print("\n[ℹ] No events found for the selected timeframe/filters.")
        return

    print(f"\n[✓] Found {total} matching events.")

    page_size = 50
    total_pages = (total + page_size - 1) // page_size
    current_page = 1

    while True:
        print(f"\n--- Page {current_page}/{total_pages} ---")
        events = fetch_events(
            es,
            indices,
            start_dt,
            end_dt,
            syscall_filter=syscall,
            comm_filter=comm,
            pid_filter=pid,
            ppid_filter=ppid,
            filename_filter=filename,
            page=current_page,
            page_size=page_size,
        )

        if not events:
            print("  (no events on this page)")
        else:
            # Show a compact table
            print(
                f"{'datetime':25} {'comm':18} {'pid':>6} {'ppid':>6} "
                f"{'syscall':12} {'filename'}"
            )
            print("-" * 90)
            for ev in events:
                dt = str(ev.get("datetime", ""))[:23]
                comm_val = str(ev.get("comm", ""))[:18]
                pid_val = str(ev.get("pid", ""))
                ppid_val = str(ev.get("ppid", ""))
                syscall_val = str(ev.get("syscall", ""))[:12]
                fname = str(ev.get("filename", ""))[:60]
                print(
                    f"{dt:25} {comm_val:18} {pid_val:>6} "
                    f"{ppid_val:>6} {syscall_val:12} {fname}"
                )

        print(
            "\nCommands: [n]ext page, [p]revious page, [q]uit to menu, or enter page number."
        )
        cmd = input("Choice: ").strip().lower()
        if cmd in ("q", "quit", "0"):
            break
        elif cmd in ("n", "next"):
            if current_page < total_pages:
                current_page += 1
            else:
                print("[ℹ] Already at last page.")
        elif cmd in ("p", "prev", "previous"):
            if current_page > 1:
                current_page -= 1
            else:
                print("[ℹ] Already at first page.")
        elif cmd.isdigit():
            page_num = int(cmd)
            if 1 <= page_num <= total_pages:
                current_page = page_num
            else:
                print("[!] Page out of range.")
        else:
            print("[!] Unrecognized command.")


def action_provenance_graph(es, config):
    if not os.path.exists(ANALYZER_SCRIPT_PATH):
        print(f"[!] Analyzer script not found: {ANALYZER_SCRIPT_PATH}")
        return

    start_dt, end_dt = prompt_time_range()

    print("\n[ Target Process ]")
    target_pid = input("  Target PID (leave blank if unknown): ").strip()
    target_comm = ""
    if not target_pid:
        target_comm = input(
            "  Target process name/comm (e.g., run-attack.sh): "
        ).strip()

    if not target_pid and not target_comm:
        print("[!] You must provide either a PID or a process name.")
        return

    print("\n[ Graph Options ]")
    depth_str = input("  Max graph depth [default 5]: ").strip()
    try:
        max_depth = int(depth_str) if depth_str else 5
    except ValueError:
        max_depth = 5

    def yes_no(prompt, default=True):
        default_str = "Y/n" if default else "y/N"
        ans = input(f"  {prompt} [{default_str}]: ").strip().lower()
        if not ans:
            return default
        if ans in ("y", "yes"):
            return True
        if ans in ("n", "no"):
            return False
        return default

    show_parents = yes_no("Include ancestor processes/parents?", True)
    show_children = yes_no("Include descendant processes/children?", True)
    prune_noise = yes_no("Prune high-degree noisy files?", True)
    disable_filtering = yes_no(
        "Disable event-level filtering in analyzer?", False
    )

    print(
        "\n[ Dependency Algorithms ] "
        "(choose at most one of the advanced options)"
    )
    print("  0) None (basic provenance graph)")
    print("  1) HOLMES backward slicing")
    print("  2) BEEP edge grouping")
    print("  3) HOLMES + BEEP (combined)")
    algo_choice = input("Select option [0-3] (default 0): ").strip() or "0"

    use_holmes = algo_choice == "1"
    use_beep = algo_choice == "2"
    use_both = algo_choice == "3"

    start_iso = start_dt.isoformat()
    end_iso = end_dt.isoformat()

    output_dir = config.get("output_dir", ".")
    os.makedirs(output_dir, exist_ok=True)
    timestamp = int(time.time())
    txt_output = os.path.join(output_dir, f"attack_summary_{timestamp}.txt")
    dot_file = os.path.join(output_dir, f"provenance_attack_{timestamp}.dot")

    cmd = [
        sys.executable,
        ANALYZER_SCRIPT_PATH,
        "--start",
        start_iso,
        "--end",
        end_iso,
        "--out",
        dot_file,
        "--text-out",
        txt_output,
        "--depth",
        str(max_depth),
        "--cli-only",
    ]

    if not show_parents:
        cmd.append("--no-parents")
    if not show_children:
        cmd.append("--no-children")
    if prune_noise:
        cmd.extend(["--prune", "--degree-threshold", "5"])
    if disable_filtering:
        cmd.append("--no-filter")
    if use_holmes:
        cmd.append("--holmes")
    if use_beep:
        cmd.append("--beep")
    if use_both:
        cmd.append("--both")

    if target_pid:
        cmd.extend(["--pid", target_pid])
    else:
        cmd.extend(["--comm", target_comm])

    print("\n[ Running analyzer.py ]")
    print("Command:", " ".join(cmd))
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        print("[!] Analysis timed out (>5 minutes).")
        return
    except Exception as e:
        print(f"[!] Error running analyzer: {e}")
        return

    print("\n--- analyzer.py STDOUT ---")
    print(result.stdout)
    if result.stderr:
        print("\n--- analyzer.py STDERR ---", file=sys.stderr)
        print(result.stderr, file=sys.stderr)

    stats = parse_analyzer_stats(result.stdout)
    if stats.get("events_loaded", 0) > 0:
        print("\n[ Analysis Statistics ]")
        print(f"  Events Loaded   : {stats['events_loaded']}")
        print(
            f"  Events Filtered : {stats['events_filtered']} "
            f"({stats['filter_percentage']:.1f}% reduction)"
        )
        print(f"  Graph Nodes     : {stats['nodes']}")
        print(f"  Graph Edges     : {stats['edges']}")

    if os.path.exists(txt_output):
        print(f"\n[✓] Text attack summary written to: {txt_output}")
    if os.path.exists(dot_file):
        print(f"[✓] DOT graph written to: {dot_file}")
        print(
            "    To render a PNG: "
            f"dot -Tpng {dot_file} -o graph.png && xdg-open graph.png"
        )


def action_statistics(es, index_base):
    if es is None:
        print("[!] Elasticsearch is not connected. Cannot compute statistics.")
        return

    start_dt, end_dt = prompt_time_range()
    indices = get_index_names(start_dt.date(), end_dt.date(), index_base)

    agg_query = {
        "query": {
            "range": {
                "datetime": {
                    "gte": start_dt.isoformat(),
                    "lte": end_dt.isoformat(),
                }
            }
        },
        "aggs": {
            "syscalls": {"terms": {"field": "syscall", "size": 50}},
            "processes": {"terms": {"field": "comm", "size": 20}},
            "timeline": {
                "date_histogram": {
                    "field": "datetime",
                    "fixed_interval": "1h",
                }
            },
        },
        "size": 0,
    }

    syscall_counts = {}
    process_counts = {}
    timeline_data = []

    try:
        for index in indices:
            if not es.indices.exists(index=index):
                continue
            response = es.search(index=index, body=agg_query)

            for bucket in response["aggregations"]["syscalls"]["buckets"]:
                syscall_counts[bucket["key"]] = (
                    syscall_counts.get(bucket["key"], 0) + bucket["doc_count"]
                )

            for bucket in response["aggregations"]["processes"]["buckets"]:
                process_counts[bucket["key"]] = (
                    process_counts.get(bucket["key"], 0) + bucket["doc_count"]
                )

            for bucket in response["aggregations"]["timeline"]["buckets"]:
                timeline_data.append(
                    {
                        "timestamp": bucket["key_as_string"],
                        "count": bucket["doc_count"],
                    }
                )
    except Exception as e:
        print(f"[!] Error generating statistics: {e}")
        return

    if not syscall_counts:
        print("\n[ℹ] No syscall data found in the selected timeframe.")
        return

    print("\n[ System Statistics ]")
    total_events = sum(syscall_counts.values())
    print(f"  Unique syscalls : {len(syscall_counts)}")
    print(f"  Unique processes: {len(process_counts)}")
    print(f"  Total events    : {total_events}")

    print("\n  Top syscalls:")
    for name, count in sorted(
        syscall_counts.items(), key=lambda x: x[1], reverse=True
    )[:20]:
        print(f"    {name:20} {count}")

    print("\n  Top processes:")
    for name, count in sorted(
        process_counts.items(), key=lambda x: x[1], reverse=True
    )[:20]:
        print(f"    {name:20} {count}")

    if timeline_data:
        print("\n  Event timeline (hourly buckets):")
        for item in sorted(
            timeline_data, key=lambda x: x["timestamp"]
        ):
            print(f"    {item['timestamp']}  {item['count']} events")


def action_ai_chat(config):
    output_dir = config.get("output_dir", ".")
    ollama_host = OLLAMA_DEFAULT_HOST

    print("\n[ AI-Powered Attack Analysis Chat ]")
    connected, models_full, models_simple = check_ollama_connection(
        ollama_host
    )
    if not connected:
        print(
            f"[!] Cannot connect to Ollama at {ollama_host}. "
            "Ensure it is running (e.g., `ollama serve`)."
        )
        return

    print("Available models (full names):")
    for name in models_full:
        print(f"  - {name}")

    default_model = models_full[0] if models_full else "llama3.2"
    model = (
        input(f"Model to use [default {default_model}]: ").strip()
        or default_model
    )
    # Try to load the latest attack summary and DOT graph as context
    context_text = ""
    dot_text = ""
    try:
        if os.path.isdir(output_dir):
            txt_candidates = [
                os.path.join(output_dir, f)
                for f in os.listdir(output_dir)
                if f.startswith("attack_summary_") and f.endswith(".txt")
            ]
            dot_candidates = [
                os.path.join(output_dir, f)
                for f in os.listdir(output_dir)
                if f.startswith("provenance_attack_") and f.endswith(".dot")
            ]

            if txt_candidates:
                latest_txt = max(txt_candidates, key=os.path.getmtime)
                with open(latest_txt, "r") as f:
                    context_text = f.read()
                print(
                    f"\n[✓] Loaded latest attack summary as context: {latest_txt}"
                )

            if dot_candidates:
                latest_dot = max(dot_candidates, key=os.path.getmtime)
                try:
                    with open(latest_dot, "r") as f:
                        full_dot = f.read()
                    max_len = 6000
                    if len(full_dot) > max_len:
                        dot_text = (
                            full_dot[:max_len]
                            + f"\n...(DOT graph truncated from {len(full_dot)} chars)"
                        )
                    else:
                        dot_text = full_dot
                    print(
                        f"[✓] Loaded latest provenance graph (DOT) as context: {latest_dot}"
                    )
                except Exception:
                    dot_text = ""
    except Exception:
        context_text = ""
        dot_text = ""

    system_prompt = (
        "You are an expert cyber forensic analyst. "
        "You are assisting a user investigating provenance graphs and "
        "kernel telemetry from an eBPF monitor."
    )

    if context_text:
        system_prompt += (
            "\n\n---\nATTACK SUMMARY (from analyzer):\n" + context_text
        )
    if dot_text:
        system_prompt += (
            "\n\n---\nPROVENANCE GRAPH (DOT snippet):\n" + dot_text
        )

    chat_history = [
        {"role": "system", "content": system_prompt},
    ]

    print(
        "\nEnter your questions about the attack or system activity.\n"
        "Type 'exit' or 'quit' to return to the main menu.\n"
    )

    while True:
        user = input("You: ").strip()
        if not user:
            continue
        if user.lower() in ("exit", "quit", "q"):
            break

        chat_history.append({"role": "user", "content": user})

        conversation = ""
        for msg in chat_history:
            role = msg["role"]
            if role == "system":
                conversation += f"System Context:\n{msg['content']}\n\n"
            elif role == "user":
                conversation += f"User: {msg['content']}\n\n"
            elif role == "assistant":
                conversation += f"Assistant: {msg['content']}\n\n"
        conversation += "Assistant:"

        print("\n[AI] Thinking...\n")
        response = query_ollama(
            conversation,
            model=model,
            host=ollama_host,
        )
        print(response, "\n")
        chat_history.append({"role": "assistant", "content": response})


def action_cleanup(es, config):
    events_dir = config.get("events_dir", ".")
    index_base = config.get("es_index", "ebpf-events")

    print("\n[ Session Reset & Data Cleanup ]")
    print(
        "This will trim the local JSONL log (ebpf_events.jsonl) and "
        "delete old documents from Elasticsearch."
    )

    amount_str = input(
        "Keep only the last N units (N) [default 1]: "
    ).strip()
    try:
        amount = int(amount_str) if amount_str else 1
    except ValueError:
        amount = 1

    unit = (
        input(
            "Time unit [Hours/Days/Months/Years] (default Hours): "
        ).strip()
        or "Hours"
    )

    delta = compute_time_delta(amount, unit)
    cutoff_dt = datetime.now(LOCAL_TZ) - delta

    total, kept, file_err = prune_event_logs(events_dir, cutoff_dt)
    es_deleted, es_err = delete_old_events_from_es(
        es, index_base, cutoff_dt
    )

    if file_err:
        print(f"[!] Local log cleanup error: {file_err}")
    else:
        removed = total - kept
        print(
            f"[✓] Local JSONL trimmed: removed {removed} events, kept {kept}."
        )

    if es_err:
        print(f"[!] Elasticsearch cleanup error: {es_err}")
    else:
        print(
            f"[✓] Deleted {es_deleted} Elasticsearch documents older than "
            f"{amount} {unit.lower()}."
        )


# Main menu

def main():
    config = load_config()
    es = connect_elasticsearch(config)
    index_base = config.get("es_index", "ebpf-events")

    print("\n=== eBPF Forensic Monitor (CLI) ===")
    print("This CLI mirrors the Streamlit UI features, but in the terminal.")

    while True:
        print("\nMain Menu:")
        print("  1) View raw event logs")
        print("  2) Build attack provenance graph")
        print("  3) View syscall/process statistics")
        print("  4) AI attack analysis chat")
        print("  5) Reset session & clean old data")
        print("  0) Exit")

        choice = input("Select an option: ").strip()

        if choice == "1":
            action_view_logs(es, index_base)
        elif choice == "2":
            action_provenance_graph(es, config)
        elif choice == "3":
            action_statistics(es, index_base)
        elif choice == "4":
            action_ai_chat(config)
        elif choice == "5":
            action_cleanup(es, config)
        elif choice in ("0", "q", "quit", "exit"):
            print("Exiting CLI. Goodbye.")
            break
        else:
            print("[!] Invalid option. Please choose from the menu.")


if __name__ == "__main__":
    main()
