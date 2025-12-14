import sys

import streamlit as st
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta, timezone
import pandas as pd
import json
import os
import subprocess
import urllib3
import networkx as nx
from pyvis.network import Network
import streamlit.components.v1 as components
import tempfile
import pydot
import time
import re
import requests

def _patch_pydot_get_strict():
    """Ensure pydot Graph.get_strict ignores unexpected arguments (networkx bug workaround)."""
    try:
        original = pydot.Graph.get_strict
    except AttributeError:
        return

    # Avoid patching repeatedly
    if getattr(original, "_patched", False):
        return

    def _patched(self, *args, **kwargs):
        return original(self)

    _patched._patched = True
    pydot.Graph.get_strict = _patched
    if hasattr(pydot, "Dot"):
        pydot.Dot.get_strict = _patched

_patch_pydot_get_strict()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONFIG_PATH = "./conf/config.json"
ANALYZER_SCRIPT_PATH = "./analyzer.py"
LOCAL_TZ = datetime.now().astimezone().tzinfo or timezone.utc
OLLAMA_DEFAULT_HOST = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434")

GRAPH_CATEGORY_STYLES = {
    "target_process": {
        "label": "Target process",
        "description": "Process under investigation",
        "color": "#2ED47A",
        "border": "#047857",
        "highlight": "#24B56A",
        "size": 36
    },
    "ancestor_process": {
        "label": "Ancestor processes",
        "description": "Parent lineage leading to target",
        "color": "#FACC15",
        "border": "#B45309",
        "highlight": "#EAB308",
        "size": 28
    },
    "descendant_process": {
        "label": "Descendant processes",
        "description": "Child activity spawned by target",
        "color": "#60A5FA",
        "border": "#1D4ED8",
        "highlight": "#3B82F6",
        "size": 26
    },
    "suspicious_process": {
        "label": "Active processes",
        "description": "Processes in the focus window",
        "color": "#A78BFA",
        "border": "#5B21B6",
        "highlight": "#8B5CF6",
        "size": 24
    },
    "benign_process": {
        "label": "Benign/noisy processes",
        "description": "Known-good helper processes",
        "color": "#CBD5F5",
        "border": "#4B5563",
        "highlight": "#A5B4FC",
        "size": 22
    },
    "sensitive_file": {
        "label": "Sensitive files",
        "description": "Protected data & credentials",
        "color": "#F87171",
        "border": "#B91C1C",
        "highlight": "#EF4444",
        "size": 22
    },
    "staging_file": {
        "label": "Temp / staging files",
        "description": "Downloads, /tmp, or cache",
        "color": "#FDBA74",
        "border": "#C2410C",
        "highlight": "#FB923C",
        "size": 22
    },
    "regular_file": {
        "label": "Regular files",
        "description": "Standard filesystem artifacts",
        "color": "#E5E7EB",
        "border": "#6B7280",
        "highlight": "#D1D5DB",
        "size": 20
    },
    "network_node": {
        "label": "Network endpoints",
        "description": "Remote hosts or sockets",
        "color": "#F472B6",
        "border": "#BE185D",
        "highlight": "#EC4899",
        "size": 24
    },
    "beep_group": {
        "label": "Aggregated activity",
        "description": "BEEP-compressed behaviors",
        "color": "#FCD34D",
        "border": "#B45309",
        "highlight": "#FBBF24",
        "size": 26
    },
    "other_node": {
        "label": "Other entities",
        "description": "Miscellaneous objects",
        "color": "#A5F3FC",
        "border": "#0E7490",
        "highlight": "#67E8F9",
        "size": 20
    }
}

GRAPH_LEGEND_ORDER = [
    "target_process",
    "ancestor_process",
    "descendant_process",
    "benign_process",
    "suspicious_process",
    "sensitive_file",
    "staging_file",
    "regular_file",
    "network_node",
    "beep_group"
]


def _safe_float(value, default=1.0):
    try:
        cleaned = str(value).replace('"', '')
        return float(cleaned)
    except (TypeError, ValueError):
        return default


def determine_node_category(node_id, attrs, focus_nodes, ancestor_nodes, descendant_nodes):
    beep_flag = attrs.get('beep_group')
    if isinstance(beep_flag, str):
        beep_flag = beep_flag.lower() in {'true', '1', 'yes'}
    if beep_flag:
        return 'beep_group'

    node_type = str(attrs.get('type', '')).lower().strip('"')
    if node_type == 'process':
        benign_flag = attrs.get('benign', False)
        if isinstance(benign_flag, str):
            benign_flag = benign_flag.lower() in {'true', '1', 'yes'}
        if node_id in focus_nodes:
            return 'target_process'
        if node_id in ancestor_nodes:
            return 'ancestor_process'
        if node_id in descendant_nodes:
            return 'descendant_process'
        if benign_flag:
            return 'benign_process'
        return 'suspicious_process'

    if node_type == 'file':
        fillcolor = str(attrs.get('fillcolor', '')).lower().strip('"')
        if fillcolor in {'#d14040', 'red'}:
            return 'sensitive_file'
        if fillcolor in {'#d18c40', 'orange'}:
            return 'staging_file'
        return 'regular_file'

    if node_type == 'network':
        return 'network_node'

    return 'other_node'


def render_graph_legend():
    legend_html = ["<div class='graph-legend'>"]
    for key in GRAPH_LEGEND_ORDER:
        style = GRAPH_CATEGORY_STYLES[key]
        swatch_style = f"background:{style['color']}; border-color:{style.get('border', style['color'])};"
        legend_html.append(
            "<div class='graph-legend-item'>"
            f"<span class='graph-legend-swatch' style='{swatch_style}'></span>"
            "<div class='graph-legend-text'>"
            f"<div class='legend-title'>{style['label']}</div>"
            f"<div class='legend-desc'>{style['description']}</div>"
            "</div></div>"
        )
    legend_html.append("</div>")
    st.markdown("".join(legend_html), unsafe_allow_html=True)

def load_config():
    if not os.path.exists(CONFIG_PATH):
        st.error(f"Config file not found at {CONFIG_PATH}")
        st.stop()
    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

@st.cache_resource
def connect_elasticsearch(config):
    es_host = config.get("es_host", "localhost:9200")
    es_user = config.get("es_user", None)
    es_pass = config.get("es_password", None)
    
    if not es_host.startswith(('http://', 'https://')):
        es_host = f"http://{es_host}"
    
    try:
        es = Elasticsearch(es_host, basic_auth=(es_user, es_pass), verify_certs=False, request_timeout=10)
        if not es.ping():
            st.error("Cannot connect to Elasticsearch")
            st.stop()
        return es
    except Exception as e:
        st.error(f"Elasticsearch connection error: {e}")
        st.stop()

def get_index_names(start_date, end_date, base_name):
    indices = []
    current = start_date
    while current <= end_date:
        index_name = f"{base_name}-{current.strftime('%Y.%m.%d')}"
        indices.append(index_name)
        current += timedelta(days=1)
    return indices

def create_interactive_graph(dot_file_path):
    """Parse DOT file and create an interactive Pyvis network graph"""
    if not os.path.exists(dot_file_path):
        return None

    try:
        pydot_graphs = pydot.graph_from_dot_file(dot_file_path)
        if not pydot_graphs:
            return None
        
        graph = nx.DiGraph(nx.nx_pydot.from_pydot(pydot_graphs[0]))
        net = Network(height="750px", width="100%", bgcolor="#F5F7FB", font_color="#0F172A", directed=True)
        net.set_options("""
        {
          "nodes": {"font": {"size": 14}, "borderWidth": 2},
          "edges": {"color": {"inherit": true}, "smooth": {"type": "continuous"}, "arrows": {"to": {"enabled": true, "scaleFactor": 0.5}}},
          "physics": {"enabled": true, "stabilization": {"iterations": 200}, "barnesHut": {"gravitationalConstant": -8000, "centralGravity": 0.3, "springLength": 150, "springConstant": 0.04}},
          "interaction": {"hover": true, "tooltipDelay": 100, "navigationButtons": true, "keyboard": true}
        }
        """)

        node_data = list(graph.nodes(data=True))
        focus_nodes = {node_id for node_id, attrs in node_data if _safe_float(attrs.get('penwidth', '1.0')) >= 3.0}

        ancestor_nodes = set()
        descendant_nodes = set()
        for focus in focus_nodes:
            try:
                ancestor_nodes.update(nx.ancestors(graph, focus))
                descendant_nodes.update(nx.descendants(graph, focus))
            except nx.NetworkXError:
                continue

        ancestor_nodes -= focus_nodes
        descendant_nodes -= focus_nodes

        for node_id, node_attrs in node_data:
            raw_label = node_attrs.get('label', node_id)
            label = str(raw_label).strip('"').replace('\\n', '\n')
            shape = str(node_attrs.get('shape', 'box')).strip('"')
            node_type = str(node_attrs.get('type', '')).strip('"').lower()
            shape_map = {'box': 'box', 'note': 'box', 'diamond': 'diamond', 'ellipse': 'ellipse', 'box3d': 'box'}
            pyvis_shape = shape_map.get(shape, 'box')

            category = determine_node_category(node_id, node_attrs, focus_nodes, ancestor_nodes, descendant_nodes)
            style = GRAPH_CATEGORY_STYLES.get(category, GRAPH_CATEGORY_STYLES['other_node'])
            node_color = {
                "background": style['color'],
                "border": style.get('border', '#1F2937'),
                "highlight": {
                    "background": style.get('highlight', style['color']),
                    "border": style.get('border', '#1F2937')
                }
            }

            tooltip = str(node_attrs.get('tooltip', label)).strip('"').replace('\\n', '\n')
            node_size = style.get('size', 22 if node_type == 'process' else 18)
            border_width = 4 if category == 'target_process' else 2

            net.add_node(
                node_id,
                label=label,
                title=tooltip,
                color=node_color,
                shape=pyvis_shape,
                size=node_size,
                borderWidth=border_width,
                borderWidthSelected=border_width + 2
            )

        for u, v in graph.edges():
            edge_attrs = graph.edges[u, v]
            edge_label = edge_attrs.get('label', '').strip('"')
            edge_color = edge_attrs.get('color', 'gray').strip('"')
            tooltip = edge_attrs.get('tooltip', edge_label).strip('"')
            net.add_edge(u, v, label=edge_label, title=tooltip, color=edge_color)

        return net

    except Exception as e:
        st.error(f"Error creating interactive graph: {e}")
        return None

def get_total_event_count(es, indices, start_datetime, end_datetime, syscall_filter=None, comm_filter=None, pid_filter=None, ppid_filter=None, filename_filter=None):
    """Get total count of events matching the filters"""
    must_conditions = [
        {"range": {"datetime": {"gte": start_datetime.isoformat(), "lte": end_datetime.isoformat()}}}
    ]

    if syscall_filter: must_conditions.append({"term": {"syscall": syscall_filter}})
    if comm_filter: must_conditions.append({"term": {"comm": comm_filter}})
    if pid_filter: must_conditions.append({"term": {"pid": pid_filter}})
    if ppid_filter: must_conditions.append({"term": {"ppid": ppid_filter}})
    if filename_filter:
        wildcard_value = filename_filter if any(ch in filename_filter for ch in ['*', '?']) else f"*{filename_filter}*"
        must_conditions.append({"wildcard": {"filename.keyword": {"value": wildcard_value}}})

    count_query = {"query": {"bool": {"must": must_conditions}}}
    total_count = 0
    for index in indices:
        try:
            if not es.indices.exists(index=index): continue
            response = es.count(index=index, body=count_query)
            total_count += response["count"]
        except Exception:
            pass

    return total_count

def fetch_events(es, indices, start_datetime, end_datetime, syscall_filter=None, comm_filter=None, pid_filter=None, ppid_filter=None, filename_filter=None, page=1, page_size=1000):
    must_conditions = [
        {"range": {"datetime": {"gte": start_datetime.isoformat(), "lte": end_datetime.isoformat()}}}
    ]

    if syscall_filter: must_conditions.append({"term": {"syscall": syscall_filter}})
    if comm_filter: must_conditions.append({"term": {"comm": comm_filter}})
    if pid_filter: must_conditions.append({"term": {"pid": pid_filter}})
    if ppid_filter: must_conditions.append({"term": {"ppid": ppid_filter}})
    if filename_filter:
        wildcard_value = filename_filter if any(ch in filename_filter for ch in ['*', '?']) else f"*{filename_filter}*"
        must_conditions.append({"wildcard": {"filename.keyword": {"value": wildcard_value}}})

    query = {
        "query": {"bool": {"must": must_conditions}},
        "sort": [{"datetime": {"order": "desc"}}],
        "from": (page - 1) * page_size,
        "size": page_size
    }

    all_events = []
    for index in indices:
        try:
            if not es.indices.exists(index=index): continue
            response = es.search(index=index, body=query)
            for hit in response["hits"]["hits"]:
                all_events.append(hit["_source"])
        except Exception:
            pass

    return all_events

def escape_dot_value(value):
    """Escape characters that break DOT rendering."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    escaped = (
        value.replace("\\", "\\\\")
             .replace("\n", "\\n")
             .replace('"', '\\"')
             .replace(":", "\\:")
    )
    return f'"{escaped}"'

def reset_app_session_state():
    """Clear analysis-specific session state keys."""
    for key in [
        'analyzer_stdout', 'analyzer_stderr', 'analyzer_stats',
        'dot_file_path', 'text_summary', 'chat_history',
        'switch_to_ai_tab', 'ai_context_loaded', 'total_events',
        'current_page', 'ai_chat_message'
    ]:
        st.session_state.pop(key, None)

def rerun_app():
    """Trigger a Streamlit rerun, compatible with older versions."""
    rerun_fn = getattr(st, "rerun", None)
    if rerun_fn:
        rerun_fn()
    else:
        st.experimental_rerun()

def compute_time_delta(amount, unit):
    """Convert unit selection into timedelta."""
    if unit == "Minutes":
        return timedelta(minutes=amount)
    if unit == "Hours":
        return timedelta(hours=amount)
    if unit == "Days":
        return timedelta(days=amount)
    if unit == "Months":
        return timedelta(days=30 * amount)
    if unit == "Years":
        return timedelta(days=365 * amount)
    return timedelta(hours=amount)

def parse_event_datetime(dt_value):
    if not dt_value:
        return None
    try:
        parsed = datetime.fromisoformat(str(dt_value).replace('Z', '+00:00'))
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
            ignore_unavailable=True
        )
        deleted = response.get("deleted", 0)
        return deleted, None
    except Exception as e:
        return 0, f"Elasticsearch cleanup failed: {e}"

def parse_analyzer_stats(stdout_text):
    """Parse statistics from analyzer output"""
    stats = {
        'events_loaded': 0,
        'events_filtered': 0,
        'filter_percentage': 0,
        'nodes': 0,
        'edges': 0
    }

    for line in stdout_text.split('\n'):
        # Total loaded events
        if 'Loaded' in line and 'events' in line:
            match = re.search(r'Loaded (\d+)', line)
            if match:
                stats['events_loaded'] = int(match.group(1))

        # Total filtered events
        if 'Filtered' in line and '/' in line:
            match = re.search(r'Filtered (\d+)/(\d+) events \((\d+\.?\d*)%', line)
            if match:
                stats['events_filtered'] = int(match.group(1))
                stats['filter_percentage'] = float(match.group(3))

        # Graph built: nodes, edges
        if 'Graph built:' in line:
            match = re.search(r'(\d+) nodes, (\d+) edges', line)
            if match:
                stats['nodes'] = int(match.group(1))
                stats['edges'] = int(match.group(2))

        # Final graph: nodes, edges
        if 'Final graph:' in line:
            match = re.search(r'(\d+) nodes, (\d+) edges', line)
            if match:
                stats['nodes'] = int(match.group(1))
                stats['edges'] = int(match.group(2))

    return stats

def query_ollama(prompt, model="llama3.2", host="http://192.168.56.1:11434"):
    """Send a query to Ollama and get response"""
    try:
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False
        }

        response = requests.post(
            f"{host}/api/generate",
            json=payload,
            timeout=60
        )

        # Check for errors
        if response.status_code == 404:
            try:
                error_detail = response.json()
            except:
                error_detail = response.text
            return f"❌ Error 404: API endpoint not found\n\n**URL:** {response.url}\n**Response:** {error_detail}\n\n**Troubleshooting:**\n1. Verify Ollama is running: `ollama serve`\n2. Check if model exists: `ollama list`\n3. Pull the model if needed: `ollama pull {model}`\n4. Try using full model name with tag (e.g., 'llama3:latest' instead of 'llama3')"

        response.raise_for_status()
        result = response.json()
        return result.get("response", "No response from model")

    except requests.exceptions.HTTPError as e:
        try:
            error_body = e.response.json()
        except:
            error_body = e.response.text
        return f"❌ HTTP Error {e.response.status_code}: {str(e)}\n\n**Response:** {error_body}"
    except requests.exceptions.ConnectionError:
        return f"❌ Cannot connect to Ollama at {host}. Make sure Ollama is running.\n\nTry: `ollama serve`"
    except requests.exceptions.Timeout:
        return "❌ Request timed out. The model might be too slow or the prompt too long."
    except Exception as e:
        return f"❌ Unexpected error: {type(e).__name__}: {str(e)}"

def check_ollama_connection(host="http://192.168.56.1:11434"):
    """Check if Ollama is running and list available models"""
    try:
        response = requests.get(f"{host}/api/tags", timeout=5)
        response.raise_for_status()
        models = response.json().get("models", [])
        # Keep full model names with tags (e.g., llama3:latest)
        model_names = [m.get("name", "") for m in models]
        # Also provide simplified names without tags
        simplified = list(set([m.split(":")[0] for m in model_names]))
        return True, model_names, simplified
    except Exception:
        return False, [], []

# --- Streamlit App ---
st.set_page_config(page_title="eBPF Forensic Monitor", layout="wide", page_icon="🔍")


st.markdown("""
<style>
:root {
    --bg-dark: #050B18;
    --panel: #10192C;
    --panel-light: #162340;
    --accent: #5CE1E6;
    --accent-strong: #F45B69;
    --muted: #9DA9C6;
}

.stApp {
    background: radial-gradient(circle at top, rgba(92,225,230,0.08), transparent 45%), var(--bg-dark);
    color: #E5ECF5;
}

div[data-testid="stSidebar"] {
    background-color: #0F172A;
}

/* Hero Card */
.hero-card {
    background: linear-gradient(120deg, #132347, #0d1224);
    border: 1px solid rgba(92,225,230,0.2);
    border-radius: 18px;
    padding: 1.5rem 2rem;
    margin-bottom: 1.5rem;
    box-shadow: 0 10px 30px rgba(3,5,15,0.5);
}

.hero-card .hero-title {
    font-size: 1.8rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
    color: #E5ECF5;
}

.hero-card .hero-text {
    color: var(--muted);
    margin-bottom: 0.8rem;
}

.hero-tags span {
    background: rgba(92,225,230,0.15);
    color: #B0F9FF;
    padding: 0.2rem 0.8rem;
    border-radius: 999px;
    font-size: 0.85rem;
    margin-right: 0.4rem;
}

/* Metric Grid */
.metric-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
}

.metric-card {
    background: var(--panel);
    border-radius: 14px;
    padding: 1rem 1.2rem;
    border: 1px solid rgba(255,255,255,0.05);
    box-shadow: inset 0 0 0 1px rgba(255,255,255,0.03);
}

.metric-label {
    color: var(--muted);
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}

.metric-value {
    font-size: 1.9rem;
    font-weight: 700;
    margin-top: 0.4rem;
    color: #F8FBFF;
}

.metric-sub {
    font-size: 0.85rem;
    color: var(--accent);
}

/* Tabs - Clean styling */
button[data-baseweb="tab"] {
    background: rgba(15,23,42,0.65);
    border-radius: 14px;
    font-size: 0.95rem;
    font-weight: 600;
    color: var(--muted);
    padding: 0.4rem 1.2rem;
    margin: 0.2rem 0.35rem 0 0;
    border: 1px solid rgba(226,232,240,0.12);
    position: relative;
    overflow: hidden;
    transition: all 0.2s ease;
}

button[data-baseweb="tab"][aria-selected="true"] {
    background: rgba(11,35,62,0.9);
    border-color: rgba(92,225,230,0.6);
    color: #F8FBFF;
    box-shadow: 0 4px 22px rgba(92,225,230,0.22);
}

.stTabs [data-baseweb="tab-highlight"] {
    display: none !important;
}

/* Primary Action Button */
.stButton > button {
    background: linear-gradient(135deg, #5CE1E6, #3A86FF);
    border: none;
    color: #050B18;
    font-weight: 700;
    border-radius: 999px;
    box-shadow: 0 10px 20px rgba(58,134,255,0.25);
    padding: 0.6rem 1.5rem;
    transition: all 0.3s ease;
}

.stButton > button:hover {
    box-shadow: 0 12px 24px rgba(58,134,255,0.35);
    transform: translateY(-2px);
}

/* Reset Button */
.reset-button > button {
    background: linear-gradient(135deg, #8B8B8B, #5C5C5C);
    border: none;
    color: #F8FBFF;
    font-weight: 600;
    border-radius: 999px;
    box-shadow: 0 8px 16px rgba(139,139,139,0.2);
    padding: 0.5rem 1.2rem;
    font-size: 0.95rem;
    transition: all 0.3s ease;
}

.reset-button > button:hover {
    background: linear-gradient(135deg, #A0A0A0, #707070);
    box-shadow: 0 10px 20px rgba(139,139,139,0.3);
    color: #F8FBFF;
}

/* Secondary Button */
.secondary-button > button {
    background: rgba(92,225,230,0.15);
    border: 1.5px solid rgba(92,225,230,0.4);
    color: #5CE1E6;
    font-weight: 600;
    border-radius: 999px;
    padding: 0.5rem 1.2rem;
    transition: all 0.3s ease;
}

.secondary-button > button:hover {
    background: rgba(92,225,230,0.25);
    border-color: rgba(92,225,230,0.8);
}

/* Danger Button */
.danger-button > button {
    background: rgba(244,91,105,0.2);
    border: 1.5px solid rgba(244,91,105,0.5);
    color: #FF9BA3;
    font-weight: 600;
    border-radius: 999px;
    padding: 0.5rem 1.2rem;
}

.danger-button > button:hover {
    background: rgba(244,91,105,0.35);
    border-color: rgba(244,91,105,0.8);
}

/* Stats Box - No red underlines */
.stats-box {
    background-color: #0E1117;
    padding: 20px;
    border-radius: 10px;
    border: 1px solid #262730;
    margin: 10px 0;
}

.stat-value {
    font-size: 2em;
    font-weight: bold;
    color: #00D9FF;
}

.stat-label {
    font-size: 0.9em;
    color: #8B8B8B;
}

.reduction-badge {
    background-color: #00B894;
    color: white;
    padding: 4px 12px;
    border-radius: 12px;
    font-size: 0.9em;
    font-weight: bold;
}

/* Fix expander styling */
.streamlit-expanderHeader {
    background: rgba(92,225,230,0.1);
    border-radius: 8px;
    transition: background 0.3s ease;
}

.streamlit-expanderHeader:hover {
    background: rgba(92,225,230,0.2);
}

.advanced-filter-spacer {
    height: 0.6rem;
}

.graph-controls-card {
    background: linear-gradient(135deg, rgba(6,12,25,0.95), rgba(11,24,45,0.95));
    border: 1px solid rgba(92,225,230,0.35);
    border-radius: 18px;
    padding: 1.35rem 1.6rem;
    box-shadow: 0 25px 45px rgba(5,10,20,0.55);
}

.graph-card-title {
    margin: 0 0 0.65rem;
    color: #F1F5FF;
    font-size: 1.18rem;
    font-weight: 600;
    letter-spacing: 0.02em;
}

.graph-card-section {
    margin-top: 0.2rem;
    margin-bottom: 0.85rem;
    color: var(--muted);
    font-size: 0.88rem;
}

.graph-card-subtitle {
    color: rgba(229,236,245,0.75);
    font-size: 0.85rem;
    margin-bottom: 1.1rem;
}

.graph-option-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 0.75rem;
    margin-bottom: 1rem;
}

.graph-option-grid .stCheckbox {
    padding: 0.65rem 0.4rem;
    background: rgba(8,14,28,0.7);
    border: 1px solid rgba(92,225,230,0.2);
    border-radius: 10px;
}

.graph-option-grid label {
    font-weight: 600;
    color: #E5ECF5 !important;
}

.graph-section-divider {
    height: 1px;
    width: 100%;
    background: linear-gradient(90deg, transparent, rgba(148,163,184,0.35), transparent);
    margin: 1rem 0 1.25rem;
}

.graph-mode-select label {
    font-weight: 600;
    color: var(--muted);
}

.section-spacer {
    height: 1.2rem;
}

.section-gap {
    height: 0.9rem;
}

.graph-legend {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 0.8rem;
    margin: 1rem 0 0.5rem;
}

.graph-legend-item {
    display: flex;
    align-items: flex-start;
    gap: 0.65rem;
    padding: 0.6rem;
    border-radius: 12px;
    background: rgba(148, 163, 184, 0.12);
    border: 1px solid rgba(148, 163, 184, 0.2);
}

.graph-legend-swatch {
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 2px solid rgba(15, 23, 42, 0.4);
    flex-shrink: 0;
}

.graph-legend-text {
    display: flex;
    flex-direction: column;
    gap: 0.1rem;
}

.legend-title {
    font-weight: 600;
    color: #F8FBFF;
    font-size: 0.95rem;
}

.legend-desc {
    font-size: 0.8rem;
    color: #9DA9C6;
}

.connection-pill-wrapper {
    height: 100%;
    display: flex;
    align-items: center;
    justify-content: flex-end;
}

.connection-pill {
    border-radius: 12px;
    font-weight: 600;
    min-height: 46px;
    padding: 0.35rem 1rem;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 6px 16px rgba(5,15,10,0.35);
    border: 1px solid rgba(255,255,255,0.08);
}

.connection-pill.success {
    background: #14532d;
    color: #d1fae5;
}

.connection-pill.error {
    background: #7f1d1d;
    color: #fee2e2;
}

</style>
""", unsafe_allow_html=True)

config = load_config()
events_dir = config.get("events_dir", ".")
output_dir = config.get("output_dir", ".")

if 'show_reset_modal' not in st.session_state:
    st.session_state['show_reset_modal'] = False
if 'reset_feedback' not in st.session_state:
    st.session_state['reset_feedback'] = ""
if 'ai_chat_message' not in st.session_state:
    st.session_state['ai_chat_message'] = ""
if 'reset_feedback_level' not in st.session_state:
    st.session_state['reset_feedback_level'] = "success"

st.title("eBPF Forensic Monitor")

# st.markdown("""
# <div class="hero-card">
#     <div class="hero-title">Provenance Graph Exploration and Forensic Triage</div>
#     <div class="hero-tags">
#         <span>Kernel Telemetry</span>
#         <span>Noise-Aware Provenance Graphs</span>
#         <span>LLM Summarization</span>
#     </div>
# </div>
# """, unsafe_allow_html=True)

hero_stats = st.session_state.get('analyzer_stats', {})
filtered_pct = hero_stats.get('filter_percentage', 0.0)
stat_cards = [
    ("Events Loaded", f"{hero_stats.get('events_loaded', 0):,}", ""),
    ("Filtered Events", f"{hero_stats.get('events_filtered', 0):,}", f"-{filtered_pct:.1f}%"),
    ("Graph Nodes", f"{hero_stats.get('nodes', 0):,}", ""),
    ("Graph Edges", f"{hero_stats.get('edges', 0):,}", "")
]

metric_html = "<div class='metric-grid'>"
for label, value, sub in stat_cards:
    metric_html += f"<div class='metric-card'><div class='metric-label'>{label}</div><div class='metric-value'>{value}</div>"
    if sub and hero_stats.get('events_filtered', 0) > 0:
        metric_html += f"<div class='metric-sub'>{sub}</div>"
    metric_html += "</div>"
metric_html += "</div>"
st.markdown(metric_html, unsafe_allow_html=True)

es = connect_elasticsearch(config)
index_base = config.get("es_index", "ebpf-events")

# Ensure output directory exists
os.makedirs(output_dir, exist_ok=True)

# Sidebar: Time and filters
st.sidebar.header("Time Range")
preset = st.sidebar.selectbox("Quick Select", ["Last 1 Hour", "Last 24 Hours", "Today", "Custom"])

local_now = datetime.now(LOCAL_TZ)

if preset == "Last 1 Hour":
    end_dt = local_now
    start_dt = end_dt - timedelta(hours=1)
elif preset == "Last 24 Hours":
    end_dt = local_now
    start_dt = end_dt - timedelta(hours=24)
elif preset == "Today":
    end_dt = local_now
    start_dt = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
else:
    start_dt = local_now - timedelta(hours=1)
    end_dt = local_now

start_date = st.sidebar.date_input("Start Date", start_dt.date())
start_time = st.sidebar.time_input("Start Time", start_dt.time())
end_date = st.sidebar.date_input("End Date", end_dt.date())
end_time = st.sidebar.time_input("End Time", end_dt.time())

start_datetime = datetime.combine(start_date, start_time).replace(tzinfo=LOCAL_TZ)
end_datetime = datetime.combine(end_date, end_time).replace(tzinfo=LOCAL_TZ)

if start_datetime >= end_datetime:
    st.sidebar.error("Start time must be before end time!")
    st.stop()

st.sidebar.markdown("---")
st.sidebar.header("Search Filters")
syscall_search = st.sidebar.text_input("Syscall", placeholder="e.g., openat")
comm_search = st.sidebar.text_input("Command", placeholder="e.g., bash")
pid_search = st.sidebar.text_input("PID", placeholder="e.g., 10466")
ppid_search = st.sidebar.text_input("PPID", placeholder="e.g., 28406")
filename_search = st.sidebar.text_input("Filename Contains", placeholder="e.g., secret.txt")

# Main tabs
tab1, tab2, tab3, tab4 = st.tabs(["Raw Log Viewer", "Attack Provenance Graph", "Statistics", "AI Analysis Chat"])

# --- tab 1: Raw Logs ---
with tab1:
    st.header("Raw Event Logs")
    st.markdown("<div class='section-gap'></div>", unsafe_allow_html=True)
    if 'total_events' not in st.session_state:
        st.session_state['total_events'] = 0
    if 'current_page' not in st.session_state:
        st.session_state['current_page'] = 1

    page_size = 1000
    if st.button("Fetch Logs", type="primary"):
        with st.spinner("Counting total events..."):
            indices = get_index_names(start_date, end_date, index_base)
            pid_int = int(pid_search) if pid_search.isdigit() else None
            ppid_int = int(ppid_search) if ppid_search.isdigit() else None
            filename_filter = filename_search.strip() or None

            # Get total count
            total_count = get_total_event_count(
                es, indices, start_datetime, end_datetime,
                syscall_search or None,
                comm_search or None,
                pid_int, ppid_int,
                filename_filter
            )
            if total_count == 0:
                st.info("No events found in the selected timeframe with the given filters.")

            st.session_state['total_events'] = total_count
            st.session_state['current_page'] = 1

    if st.session_state['total_events'] > 0:
        total_pages = (st.session_state['total_events'] + page_size - 1) // page_size

        # Display total stats
        st.info(f"Total events in timeframe: **{st.session_state['total_events']:,}** | Page {st.session_state['current_page']} of {total_pages}")

        # Pagination controls
        page_num = st.number_input("Go to page", min_value=1, max_value=total_pages,
                                    value=st.session_state['current_page'], key='page_input')
        if page_num != st.session_state['current_page']:
            st.session_state['current_page'] = page_num
            rerun_app()

        with st.spinner(f"Loading page {st.session_state['current_page']}..."):
            # Regenerate indices for the current timeframe
            indices = get_index_names(start_date, end_date, index_base)
            pid_int = int(pid_search) if pid_search.isdigit() else None
            ppid_int = int(ppid_search) if ppid_search.isdigit() else None
            filename_filter = filename_search.strip() or None
            events = fetch_events(
                es, indices, start_datetime, end_datetime,
                syscall_search or None,
                comm_search or None,
                pid_int, ppid_int,
                filename_filter,
                page=st.session_state['current_page'],
                page_size=page_size
            )
            if events:
                df = pd.DataFrame(events)
                cols = ['datetime', 'comm', 'pid', 'ppid', 'syscall', 'filename', 'fd', 'ret']
                cols = [c for c in cols if c in df.columns]

                start_idx = (st.session_state['current_page'] - 1) * page_size + 1
                end_idx = min(start_idx + len(events) - 1, st.session_state['total_events'])
                st.caption(f"Showing events {start_idx:,} to {end_idx:,}")

                # Reset index to start from the actual event number (not 0)
                df.index = range(start_idx, start_idx + len(df))
                st.dataframe(df[cols])

                # Download option
                csv = df.to_csv(index=False)
                st.download_button(
                    label="Download Current Page CSV",
                    data=csv,
                    file_name=f"events_page_{st.session_state['current_page']}.csv",
                    mime="text/csv"
                )
            else:
                st.warning("No events found on this page.")

# --- tab 2: Provenance Graph ---
with tab2:
    st.header("Attack Path Provenance Graph")
    
    # Main controls
    col1, col2 = st.columns([1, 1])
    with col1:
        target_comm = st.text_input("Target Process Name", value="run-attack.sh", help="Name of the suspicious process (e.g., bash)")
    with col2:
        target_pid = st.text_input("Target PID", help="PID of the suspicious process (e.g., 12345)")

    max_depth = st.slider("Graph Depth", min_value=1, max_value=10, value=5, help="Maximum traversal depth in the process tree")

    # Advanced filtering options
    with st.expander("⚙️ Advanced Filters", expanded=True):
        st.markdown("", unsafe_allow_html=True)
        trav_col1, trav_col2, trav_col3, trav_col4 = st.columns(4)
        with trav_col1:
            show_parents = st.checkbox("Trace Ancestors", value=True, help="Include parent processes that led to the focus node")
        with trav_col2:
            show_children = st.checkbox("Trace Descendants", value=True, help="Follow child activity spawned from the target")
        with trav_col3:
            disable_filtering = st.checkbox(
                "Disable Event Filtering",
                value=False,
                help="Skip provenance noise filtering (surface every captured event)"
            )
        with trav_col4:
            prune_noise = st.checkbox(
                "Prune High-Degree Files",
                value=False,
                help="Remove files touched by many processes to reduce background noise"
            )

        st.markdown("", unsafe_allow_html=True)
        analysis_mode = st.selectbox(
            "Noise Filtering Algorithm",
            options=[
                "Standard",
                "HOLMES Backward Slicing",
                "BEEP Edge Grouping",
                "Both HOLMES & BEEP"
            ],
            index=0,
            help="HOLMES traces causal ancestry; BEEP collapses repetitive file edges."
        )
        st.markdown("</div>", unsafe_allow_html=True)

        use_holmes = "HOLMES" in analysis_mode
        use_beep = "BEEP" in analysis_mode
        use_both = "Both" in analysis_mode

    # Analysis button
    if st.button("Analyze & Build Graph", type="primary"):
        if not target_comm and not target_pid:
            st.error("❌ Please enter either a Target Process Name OR a Target PID.")
            st.stop()
        if target_comm and target_pid:
            st.info("ℹ️ PID and Process Name entered. Prioritizing PID.")
            target_comm = ""

        if not os.path.exists(ANALYZER_SCRIPT_PATH):
            st.error(f"Analyzer script not found: {ANALYZER_SCRIPT_PATH}")
        else:
            target_display = target_pid if target_pid else target_comm
            with st.spinner(f"Analyzing '{target_display}'"):
                try:
                    start_iso = start_datetime.isoformat()
                    end_iso = end_datetime.isoformat()

                    # Use configured output directory
                    timestamp = int(time.time())
                    TXT_OUTPUT = os.path.join(output_dir, f"attack_summary_{timestamp}.txt")
                    DOT_FILE = os.path.join(output_dir, f"provenance_attack_{timestamp}.dot")

                    cmd = [
                        "python3", ANALYZER_SCRIPT_PATH,
                        "--start", start_iso,
                        "--end", end_iso,
                        "--out", DOT_FILE,
                        "--text-out", TXT_OUTPUT,
                        "--depth", str(max_depth)
                    ]

                    if not show_parents:
                        cmd.append("--no-parents")
                    if not show_children:
                        cmd.append("--no-children")
                    if prune_noise:
                        cmd.extend(["--prune", "--degree-threshold", str(5)])
                    if disable_filtering:
                        cmd.append("--no-filter")

                    # Dependency Algorithms
                    if use_holmes:
                        cmd.append("--holmes")
                    if use_beep:
                        cmd.append("--beep")
                    if use_both:
                        cmd.append("--both")

                    if target_pid:
                        cmd.extend(["--pid", target_pid])
                    elif target_comm:
                        cmd.extend(["--comm", target_comm])

                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

                    # Store results in session state
                    st.session_state['analyzer_stdout'] = result.stdout
                    st.session_state['analyzer_stderr'] = result.stderr
                    st.session_state['analyzer_stats'] = parse_analyzer_stats(result.stdout)
                    st.session_state['analyzer_exit_code'] = result.returncode
                    
                    if os.path.exists(DOT_FILE) and os.path.getsize(DOT_FILE) > 0:
                        st.session_state['dot_file_path'] = DOT_FILE
                    else:
                        st.session_state['dot_file_path'] = None
                        if result.returncode != 0:
                            st.error(f"Analyzer exited with code {result.returncode}. Check the logs below for details.")
                        else:
                            st.warning(f"⚠️ No graph generated. Process '{target_display}' might not be in the selected time window or filters.")
                    
                    if os.path.exists(TXT_OUTPUT):
                        with open(TXT_OUTPUT, 'r') as f:
                            st.session_state['text_summary'] = f.read()
                    
                except subprocess.TimeoutExpired:
                    st.error("⏱️ Analysis timed out (>5 minutes). Try reducing the time range or graph depth.")
                    st.session_state['dot_file_path'] = None
                except Exception as e:
                    st.error(f"Error running analysis: {e}")
                    st.session_state['dot_file_path'] = None

    # Display analyzer logs
    if 'analyzer_stdout' in st.session_state:
        with st.expander("Analyzer Logs", expanded=not st.session_state.get('dot_file_path')):
            st.code(st.session_state['analyzer_stdout'], language='text')
            if st.session_state.get('analyzer_stderr'):
                st.error("Errors:")
                st.code(st.session_state['analyzer_stderr'], language='text')

    # Display statistics if available
    if 'analyzer_stats' in st.session_state:
        stats = st.session_state['analyzer_stats']
        
        st.markdown("### Analysis Statistics")
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.metric("Events Loaded", f"{stats['events_loaded']:,}")
        
        with col2:
            if stats['events_filtered'] > 0:
                st.metric("Events Filtered", f"{stats['events_filtered']:,}", 
                         delta=f"-{stats['filter_percentage']:.1f}%")
            else:
                st.metric("Events Filtered", "0")
        
        with col3:
            st.metric("Graph Nodes", f"{stats['nodes']}")
        
        with col4:
            st.metric("Graph Edges", f"{stats['edges']}")

    # Display graph if available
    if st.session_state.get('dot_file_path'):
        st.success("✅ Graph analysis complete!")

        # AI Analysis navigation button
        if st.button("🤖 Discuss with AI Assistant", type="secondary", help="Chat with AI about this attack analysis"):
            st.session_state['switch_to_ai_tab'] = True
            st.session_state['ai_context_loaded'] = False
            rerun_app()

        dot_file = st.session_state['dot_file_path']
        interactive_graph = create_interactive_graph(dot_file)
        if interactive_graph:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.html', delete=False) as f:
                interactive_graph.save_graph(f.name)
                with open(f.name, 'r', encoding='utf-8') as html_file:
                    source_code = html_file.read()
                components.html(source_code, height=800, scrolling=True)
                os.unlink(f.name)

            render_graph_legend()

            if 'text_summary' in st.session_state:
                st.markdown("---")
                st.subheader("Attack Relationship Summary")
                st.caption("Narrative of the provenance graph for quick sharing.")
                with st.expander("View Attack Relationships", expanded=False):
                    st.text_area("Attack Chain Summary", value=st.session_state['text_summary'], height=300)
                    st.download_button(
                        label="Download Summary",
                        data=st.session_state['text_summary'],
                        file_name="attack_summary.txt",
                        mime="text/plain"
                    )

            png_file = dot_file.replace(".dot", ".png")
            try:
                # Generate PNG if it doesn't exist
                if not os.path.exists(png_file):
                    subprocess.run(["dot", "-Tpng", dot_file, "-o", png_file],
                                    check=True, timeout=30, capture_output=True)

                if os.path.exists(png_file):
                    with open(png_file, 'rb') as f:
                        st.download_button(
                            label="📥 Download PNG Image",
                            data=f.read(),
                            file_name=os.path.basename(png_file),
                            mime="image/png"
                        )
            except Exception as e:
                st.warning(f"PNG generation unavailable: {e}")

        else:
            st.error("❌ Failed to create interactive graph.")

# --- tab 3: Statistics ---
with tab3:
    st.header("System Statistics")
    st.markdown("<div class='section-gap'></div>", unsafe_allow_html=True)
    if st.button("Generate Syscall Statistics", type="primary"):
        with st.spinner("Analyzing syscalls..."):
            indices = get_index_names(start_date, end_date, index_base)

            # Aggregation query for syscalls
            agg_query = {
                "query": {
                    "range": {"datetime": {"gte": start_datetime.isoformat(), "lte": end_datetime.isoformat()}}
                },
                "aggs": {
                    "syscalls": {"terms": {"field": "syscall", "size": 50}},
                    "processes": {"terms": {"field": "comm", "size": 20}},
                    "timeline": {
                        "date_histogram": {
                            "field": "datetime",
                            "fixed_interval": "1h"
                        }
                    }
                },
                "size": 0
            }

            syscall_counts = {}
            process_counts = {}
            timeline_data = []

            try:
                for index in indices:
                    if not es.indices.exists(index=index): continue
                    response = es.search(index=index, body=agg_query)

                    # Syscall counts
                    for bucket in response["aggregations"]["syscalls"]["buckets"]:
                        syscall_counts[bucket["key"]] = syscall_counts.get(bucket["key"], 0) + bucket["doc_count"]

                    # Process counts
                    for bucket in response["aggregations"]["processes"]["buckets"]:
                        process_counts[bucket["key"]] = process_counts.get(bucket["key"], 0) + bucket["doc_count"]

                    # Timeline data
                    for bucket in response["aggregations"]["timeline"]["buckets"]:
                        timeline_data.append({
                            "timestamp": bucket["key_as_string"],
                            "count": bucket["doc_count"]
                        })

                if syscall_counts:
                    # Summary stats
                    st.markdown("---")
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("Unique Syscalls", len(syscall_counts))
                    with col2:
                        st.metric("Unique Processes", len(process_counts))
                    with col3:
                        st.metric("Total Events", sum(syscall_counts.values()))

                    st.markdown("---")
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("#### Top Syscalls")
                        df_syscalls = pd.DataFrame(list(syscall_counts.items()), columns=["Syscall", "Count"])
                        df_syscalls = df_syscalls.sort_values("Count", ascending=False).head(20)
                        st.bar_chart(df_syscalls.set_index("Syscall"))

                    with col2:
                        st.markdown("#### Top Processes")
                        df_processes = pd.DataFrame(list(process_counts.items()), columns=["Process", "Count"])
                        df_processes = df_processes.sort_values("Count", ascending=False).head(20)
                        st.bar_chart(df_processes.set_index("Process"))

                    # Timeline chart
                    st.markdown("#### Event Timeline (Hourly)")
                    if timeline_data:
                        df_timeline = pd.DataFrame(timeline_data)
                        df_timeline['timestamp'] = pd.to_datetime(df_timeline['timestamp'])
                        df_timeline = df_timeline.set_index('timestamp')
                        st.line_chart(df_timeline)

                else:
                    st.warning("No syscall data found in the selected timeframe")

            except Exception as e:
                st.error(f"Error generating statistics: {e}")

    st.markdown("---")
    st.subheader("Elasticsearch Indices")
    try:
        indices_info = es.cat.indices(index=f"{index_base}*", format="json")
        if indices_info:
            df_indices = pd.DataFrame(indices_info)
            df_indices = df_indices[['index', 'docs.count', 'store.size']].sort_values('index', ascending=False)
            df_indices.columns = ['Index', 'Documents', 'Size']
            st.dataframe(df_indices)

            total_docs = df_indices['Documents'].astype(int).sum()
            st.metric("Total Events Stored", f"{total_docs:,}")
        else:
            st.info("No indices found")
    except Exception as e:
        st.error(f"Error fetching indices: {e}")
    
    
    # Noise reduction guide
    st.markdown("---")
    st.subheader("Noise Reduction Guide")
    
    with st.expander("Understanding Filtering Levels"):
        st.markdown("", unsafe_allow_html=True)
        st.markdown("""
        #### Three-Layer Filtering Strategy
        
        **Layer 1: Kernel-Level (eBPF)**
        - Filters at the source (60-70% reduction)
        - Removes: systemd, dbus, kworker, /proc, /sys, .so files
        - Zero performance overhead
                    
        **Layer 2: Application-Level**
        - Filters during graph building (15-20% reduction)
        - Entity abstraction (removes user-specific paths)
        - Context-aware decisions
                    
        **Layer 3: Graph-Level**
        - Statistical pruning (5-10% reduction)
        - Removes high-degree nodes (files accessed by many processes)
        - Configurable via "Degree Threshold"

        """)

        st.markdown("", unsafe_allow_html=True)

        st.markdown(""" 
        #### Recommended Settings
        
        **For Real-Time Monitoring (SOC):**
        - ✅ Prune High-Degree Files
        - Degree Threshold: 3-5
        - Disable Event Filtering: No
        
        **For Incident Investigation:**
        - ✅ Prune High-Degree Files
        - Degree Threshold: 7-10
        - Disable Event Filtering: No
         
        **For Forensic Analysis (Legal):**
        - ❌ Prune High-Degree Files (or Threshold: 15+)
        - Disable Event Filtering: Yes
        - Graph Depth: 10

        """)

        st.markdown("", unsafe_allow_html=True)

    with st.expander("What Gets Filtered vs. Protected"):
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("", unsafe_allow_html=True)
            st.markdown("""
            **Always Filtered:**
            - System processes (systemd, dbus, kworker)
            - Virtual filesystems (/proc, /sys)
            - Shared libraries (*.so files)
            - Desktop environment (gnome, gvfs)
            - Common system files
            """)
        
        with col2:
            st.markdown("", unsafe_allow_html=True)
            st.markdown("""
            **Never Filtered:**
            - Sensitive files (/etc/passwd, /etc/shadow)
            - User secrets (*/secret/*, */.ssh/*)
            - Attacker directories (*/attacker/*)
            - Network connections
            - Data exfiltration patterns
            """)
        st.markdown("", unsafe_allow_html=True)

# tab4: AI ChatBot
with tab4:
    st.header("AI-Powered Attack Analysis")
    
    # Initialize chat history
    if 'chat_history' not in st.session_state:
        st.session_state['chat_history'] = []

    # Check Ollama connection
    col1, col2 = st.columns([3, 1])
    with col1:
        ollama_host = st.text_input(
            "Ollama Host",
            value=OLLAMA_DEFAULT_HOST,
            help="Base URL of your Ollama server (e.g., http://localhost:11434)"
        )
        if not ollama_host:
            ollama_host = OLLAMA_DEFAULT_HOST
        st.caption("Using this Ollama LLM backend for attack summaries")
    is_connected, available_models_full, available_models_simple = check_ollama_connection(ollama_host)

    with col2:
        status_class = "success" if is_connected else "error"
        status_text = "Ollama Connected" if is_connected else "❌ Not Connected"
        st.markdown("", unsafe_allow_html=True)
        st.markdown(
            f"<div class='connection-pill-wrapper'><div class='connection-pill {status_class}'>{status_text}</div></div>",
            unsafe_allow_html=True
        )

    # Model selection
    if available_models_full:
        selected_model = st.selectbox("Select Model", options=available_models_full)
        st.caption(f"💡 Available models: {', '.join(available_models_simple)}")
    else:
        selected_model = st.text_input("Model Name", value="llama3:latest", 
                                       help="Enter model name with tag (e.g., llama3:latest)")
        if not is_connected:
            st.warning("⚠️ Ollama not connected. Start Ollama with: `ollama serve`")

    # Test connection buttons
    col_test1, col_test2 = st.columns(2)
    with col_test1:
        if st.button("Test Ollama Connection"):
            with st.spinner("Testing connection..."):
                test_response = query_ollama("Say 'Hello, I am working!' in one sentence.", 
                                            model=selected_model, host=ollama_host)
                st.info(f"**Test Response:**\n\n{test_response}")

    with col_test2:
        if st.button("Show API Info"):
            st.code("""Ollama API Endpoints (relative paths):
- /api/tags
- /api/generate
            """, language="text")

    st.markdown("---")

    # Load attack context if available
    if 'analyzer_stats' in st.session_state or 'text_summary' in st.session_state:
        # Auto-load context when switching from Tab 2
        if st.session_state.get('switch_to_ai_tab') and not st.session_state.get('ai_context_loaded'):
            st.session_state['ai_context_loaded'] = True
            st.session_state['switch_to_ai_tab'] = False

            # Build context from analysis
            context_parts = ["# Attack Analysis Context\n"]

            if 'analyzer_stats' in st.session_state:
                stats = st.session_state['analyzer_stats']
                context_parts.append(f"""
## Analysis Statistics
- Events Loaded: {stats['events_loaded']:,}
- Events Filtered: {stats['events_filtered']:,} ({stats['filter_percentage']:.1f}% reduction)
- Graph Nodes: {stats['nodes']}
- Graph Edges: {stats['edges']}
""")

            if 'text_summary' in st.session_state:
                summary = st.session_state['text_summary']
                original_length = len(summary)
                if len(summary) > 8000:
                    summary = summary[:8000] + f"\n...(attack summary truncated from {original_length} chars)"
                context_parts.append(f"\n## Attack Chain Summary\n{summary}")

            # Also include a trimmed snapshot of the DOT provenance graph if available
            dot_path = st.session_state.get('dot_file_path')
            if dot_path and os.path.exists(dot_path):
                try:
                    with open(dot_path, "r") as f:
                        dot_text = f.read()
                    original_len = len(dot_text)
                    max_len = 6000
                    if len(dot_text) > max_len:
                        dot_text = dot_text[:max_len] + f"\n...(DOT graph truncated from {original_len} chars)"
                    context_parts.append(f"\n## Provenance Graph (DOT Snippet)\n{dot_text}")
                except Exception:
                    # If anything goes wrong loading the DOT, just skip it
                    pass

            context = "\n".join(context_parts)

            # Add context as first system message
            initial_prompt = f"""
            You are an expert Cyber Forensic Analyst using the MITRE ATT&CK framework.
            Analyze the provided execution graph summary from an eBPF monitor.

            Context:
            {context}

            Your Analysis Objectives:
            1. Trace the Execution Chain: Identify the root process and sequence of spawned processes.
            2. Identify Malicious Behaviors: Look for Collection, C2/Exfiltration, Impact/Destruction, or Persistence.
            3. Analyze Noise Reduction: Explain what repetitive or noisy behavior was compressed.

            Final Output Format:
            - Attack Type: (e.g., Exfiltration, Ransomware, Dropper)
            - Critical IOCs: (List IPs, filenames, PIDs)
            - Narrative: Brief chronological story of what happened.

            Based on the logs, provide your analysis:"""

            # Get initial AI response
            with st.spinner("Loading attack context into AI..."):
                ai_response = query_ollama(initial_prompt, model=selected_model, host=ollama_host)
                st.session_state['chat_history'] = [
                    {"role": "system", "content": context},
                    {"role": "assistant", "content": ai_response}
                ]

        # Show context loaded indicator
        with st.expander("Attack Context Loaded", expanded=False):
            st.markdown("", unsafe_allow_html=True)
            st.markdown("", unsafe_allow_html=True)
            if 'analyzer_stats' in st.session_state:
                stats = st.session_state['analyzer_stats']
                col1, col2, col3, col4 = st.columns(4)
                with col1:
                    st.metric("Events", f"{stats['events_loaded']:,}")
                with col2:
                    st.metric("Filtered", f"{stats['filter_percentage']:.1f}%")
                with col3:
                    st.metric("Nodes", stats['nodes'])
                with col4:
                    st.metric("Edges", stats['edges'])

            if 'text_summary' in st.session_state:
                summary = st.session_state['text_summary']
                summary_length = len(summary)
                lines = summary.count('\n')
                st.caption(f"Attack summary: {summary_length:,} chars, {lines} lines")

                show_full_summary = st.checkbox(
                    "Show full attack summary context",
                    value=False,
                    key="show_full_summary"
                )
                if show_full_summary:
                    st.text_area("Full Context Loaded into AI", value=summary, height=400)
                    st.markdown("", unsafe_allow_html=True)

            col_reload1, col_reload2 = st.columns(2)
            with col_reload1:
                if st.button("🔄 Reload Context"):
                    st.session_state['ai_context_loaded'] = False
                    st.session_state['switch_to_ai_tab'] = True
                    rerun_app()
            with col_reload2:
                if st.button("📋 Copy Context to Clipboard"):
                    if 'text_summary' in st.session_state:
                        st.code(st.session_state['text_summary'], language='text')
            st.markdown("", unsafe_allow_html=True)
    else:
        st.info("💡 Run an attack analysis in the 'Attack Provenance Graph' tab first")

    st.markdown("### 💬 Chat History")

    # Display chat history (NOT in expander or container)
    for message in st.session_state.get('chat_history', []):
        if message['role'] == 'system':
            continue

        if message['role'] == 'user':
            with st.chat_message("user"):
                st.markdown(message['content'])
        elif message['role'] == 'assistant':
            with st.chat_message("assistant"):
                st.markdown(message['content'])

    # Debug toggle
    show_debug = st.checkbox("Show debug info (conversation sent to AI)", value=False)

    chat_input_col, chat_action_col = st.columns([5, 1])
    with chat_input_col:
        st.text_input(
            "Ask about the attack analysis...",
            key="ai_chat_message",
            placeholder="Describe what you want to know about this attack",
            label_visibility="collapsed"
        )
    with chat_action_col:
        send_clicked = st.button("Send", key="send_ai_chat")

    user_input = st.session_state.get('ai_chat_message', '').strip()

    if send_clicked:
        if not user_input:
            st.warning("Enter a message before sending.")
        elif not is_connected:
            st.error("❌ Cannot send message: Ollama is not connected")
        else:
            # Add user message to history
            st.session_state['chat_history'].append({"role": "user", "content": user_input})

            # Build conversation context
            conversation = ""
            for msg in st.session_state['chat_history']:
                if msg['role'] == 'system':
                    conversation += f"System Context:\n{msg['content']}\n\n"
                elif msg['role'] == 'user':
                    conversation += f"User: {msg['content']}\n\n"
                elif msg['role'] == 'assistant':
                    conversation += f"Assistant: {msg['content']}\n\n"

            conversation += f"User: {user_input}\n\nAssistant:"

            # Show debug info if enabled
            if show_debug:
                with st.expander("🔍 Debug: Full Conversation Sent to AI", expanded=False):
                    st.text_area("Conversation", value=conversation, height=300)
                    st.caption(f"Total length: {len(conversation):,} chars")

            # Get AI response
            with st.spinner("Thinking..."):
                ai_response = query_ollama(conversation, model=selected_model, host=ollama_host)

            # Add AI response to history
            st.session_state['chat_history'].append({"role": "assistant", "content": ai_response})

            # Clear input and rerun to display new messages
            rerun_app()

    # Clear chat button
    if st.session_state.get('chat_history'):
        if st.button("🗑️ Clear Chat"):
            st.session_state['chat_history'] = []
            st.session_state['ai_context_loaded'] = False
            rerun_app()

st.markdown("---")
st.subheader("Session Reset & Data Cleanup")
st.markdown("<div class='section-gap'></div>", unsafe_allow_html=True)

if st.session_state.get('reset_feedback'):
    level = st.session_state.get('reset_feedback_level', 'success')
    message = st.session_state.pop('reset_feedback')
    if level == 'error':
        st.error(message)
    else:
        st.success(message)
    st.session_state['reset_feedback_level'] = "success"

reset_button_container = st.container()
with reset_button_container:
    st.markdown('<div class="reset-button" style="text-align:right;">', unsafe_allow_html=True)
    if st.button("Reset Session & Logs", key="open_reset_modal"):
        st.session_state['show_reset_modal'] = True
    st.markdown('</div>', unsafe_allow_html=True)

reset_modal_placeholder = st.empty()
if st.session_state.get('show_reset_modal'):
    with reset_modal_placeholder.container():
        st.markdown("### Reset session & trim logs")
        st.caption("Remove cached results, truncate the local JSONL file, and delete Elasticsearch events older than your chosen window.")
        with st.form("reset_form", clear_on_submit=False):
            keep_amount = st.number_input(
                "Keep only the last ...",
                min_value=1,
                max_value=720,
                value=st.session_state.get('reset_amount', 1),
                key="reset_amount_input"
            )
            keep_unit = st.selectbox(
                "Time unit",
                ["Minutes", "Hours", "Days", "Months", "Years"],
                index=0,
                key="reset_unit_input"
            )
            submitted = st.form_submit_button("Confirm & Clear")

        cancel = st.button("Cancel", key="cancel_reset")

        if submitted:
            delta = compute_time_delta(keep_amount, keep_unit)
            cutoff_dt = datetime.now(LOCAL_TZ) - delta
            total, kept, file_err = prune_event_logs(events_dir, cutoff_dt)
            es_deleted, es_err = delete_old_events_from_es(es, index_base, cutoff_dt)
            reset_app_session_state()
            st.session_state['show_reset_modal'] = False

            errors = [msg for msg in [file_err, es_err] if msg]
            if errors:
                st.session_state['reset_feedback'] = " | ".join(errors)
                st.session_state['reset_feedback_level'] = "error"
            else:
                removed = total - kept
                st.session_state['reset_feedback'] = (
                    f"Session reset. Removed {removed} local events and deleted {es_deleted} Elasticsearch documents older than "
                    f"{keep_amount} {keep_unit.lower()}."
                )
                st.session_state['reset_feedback_level'] = "success"
            rerun_app()

        if cancel:
            st.session_state['show_reset_modal'] = False
            rerun_app()

# Footer
st.markdown("---")

footer_html = """
<style>
footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
}
footer:after {
    content: "Developed by Amish, Samih and Satya";
    font-weight: 400;
    margin-left: auto;
}
/* Restore spacing between "Made with" text node and the Streamlit link */
footer a {
    margin-left: 0.25rem;
}
</style>
"""
st.markdown(footer_html, unsafe_allow_html=True)
