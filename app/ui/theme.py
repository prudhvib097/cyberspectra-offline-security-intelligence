"""CyberSpectra design system: one token set, two themes, fully offline.

No remote fonts, no CDN. Everything is a CSS custom property so charts, tables,
notifications and Streamlit's own widgets all read from the same tokens.
Spacing scale: 4 / 8 / 12 / 16 / 24 px.
"""

from __future__ import annotations

THEMES = ("light", "dark")
DEFAULT_THEME = "light"

TOKENS: dict[str, dict[str, str]] = {
    "light": {
        "bg": "#eef1f5", "surface": "#ffffff", "surface2": "#f5f7fa", "border": "#d9e0e8", "border2": "#c4cdd8",
        "text": "#0f2238", "muted": "#566a80", "accent": "#0a8f98", "accent_soft": "#e1f4f5", "accent_text": "#ffffff",
        "critical": "#d32f3f", "high": "#e8710a", "medium": "#d99a00", "low": "#2e9b57",
        "critical_soft": "#fdecee", "high_soft": "#fdf0e3", "medium_soft": "#fdf5dc", "low_soft": "#e6f5ec",
        "shadow": "0 1px 2px rgba(15,34,56,.06)", "grid": "#e6ebf1",
    },
    "dark": {
        "bg": "#0b1220", "surface": "#121b2c", "surface2": "#17233a", "border": "#243350", "border2": "#32456a",
        "text": "#e8eef6", "muted": "#8fa1b8", "accent": "#2cc3cc", "accent_soft": "#12353e", "accent_text": "#06202a",
        "critical": "#ff5a67", "high": "#ff9442", "medium": "#f2b823", "low": "#43c27a",
        "critical_soft": "#3a1a22", "high_soft": "#3a2716", "medium_soft": "#372f12", "low_soft": "#14301f",
        "shadow": "none", "grid": "#1f2d47",
    },
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def severity_color(theme: str, severity: str) -> str:
    return TOKENS[theme].get(severity.lower(), TOKENS[theme]["muted"])


FONT_STACK = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif'
MONO_STACK = 'ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace'


def build_css(theme: str, active_page: str) -> str:
    t = TOKENS.get(theme, TOKENS[DEFAULT_THEME])
    variables = "".join(f"--{key.replace('_', '-')}:{value};" for key, value in t.items())
    return f"""
<style>
:root {{ {variables} --font:{FONT_STACK}; --mono:{MONO_STACK}; color-scheme:{theme}; }}

/* ---------- base + Streamlit chrome ---------- */
html, body, .stApp, [data-testid="stAppViewContainer"], [data-testid="stMain"] {{ background:var(--bg) !important; color:var(--text); font-family:var(--font); }}
.stApp * {{ font-family:var(--font); }}
.stApp [data-testid="stIconMaterial"], .stApp .material-icons, .stApp .material-symbols-rounded, .stApp [class*="material-symbols"] {{ font-family:"Material Symbols Rounded","Material Symbols Outlined" !important; }}
[data-testid="stHeader"], [data-testid="stToolbar"], [data-testid="stDecoration"], footer,
[data-testid="stSidebar"], [data-testid="collapsedControl"], [data-testid="stSidebarCollapsedControl"] {{ display:none !important; }}
.block-container {{ max-width:100% !important; padding:12px 20px 24px !important; }}
[data-testid="stVerticalBlock"] {{ gap:12px !important; }}
[data-testid="stHorizontalBlock"] {{ gap:12px !important; }}
.stApp, .stApp p, .stApp li, .stApp label, .stApp span, .stApp div {{ color:inherit; }}
[data-testid="stMarkdownContainer"] {{ margin-bottom:0 !important; }}
.stMarkdown p {{ font-size:14px; line-height:1.5; margin:0 0 4px; }}
a {{ color:var(--accent); }}
hr {{ border-color:var(--border) !important; margin:12px 0 !important; }}

/* ---------- unified header ---------- */
.st-key-app-header {{ background:var(--surface); border:1px solid var(--border); border-radius:8px 8px 0 0; padding:0 16px; min-height:68px; justify-content:center; box-shadow:var(--shadow); }}
.st-key-app-header [data-testid="stHorizontalBlock"] {{ align-items:center; gap:12px; }}
.cs-brand {{ display:flex; align-items:center; gap:12px; line-height:1.15; }}
.cs-brand svg {{ flex:0 0 auto; }}
.cs-brand-name {{ font-size:24px; font-weight:800; letter-spacing:.08em; color:var(--text); }}
.cs-brand-sub {{ font-size:14px; color:var(--muted); margin-top:2px; }}
.cs-status {{ display:flex; justify-content:flex-end; align-items:center; gap:20px; flex-wrap:nowrap; white-space:nowrap; font-size:14px; font-weight:600; color:var(--text); letter-spacing:.03em; }}
.cs-status span {{ display:inline-flex; align-items:center; gap:8px; }}
.cs-dot {{ width:9px; height:9px; border-radius:50%; background:var(--muted); display:inline-block; }}
.cs-dot.ok {{ background:var(--low); }} .cs-dot.warn {{ background:var(--medium); }} .cs-dot.bad {{ background:var(--critical); }} .cs-dot.info {{ background:var(--accent); }}

/* ---------- navigation (connected to the header) ---------- */
.st-key-app-nav {{ background:var(--surface); border:1px solid var(--border); border-top:0; border-radius:0 0 8px 8px; padding:0 16px; min-height:52px; justify-content:center; box-shadow:var(--shadow); margin-bottom:4px; }}
.st-key-app-nav [data-testid="stHorizontalBlock"] {{ gap:4px; align-items:stretch; }}
.st-key-app-nav .stButton button {{ background:transparent; border:0; border-bottom:3px solid transparent; border-radius:0; box-shadow:none; color:var(--muted); font-size:16px; font-weight:600; min-height:50px; padding:0 8px; width:100%; }}
.st-key-app-nav .stButton button p {{ font-size:16px; font-weight:600; color:inherit; margin:0; }}
.st-key-app-nav .stButton button:hover {{ color:var(--text); background:var(--surface2); }}
.st-key-nav-{active_page} button {{ color:var(--accent) !important; border-bottom-color:var(--accent) !important; background:var(--accent-soft) !important; }}
.st-key-nav-{active_page} button p {{ color:var(--accent) !important; }}
.st-key-app-header .stButton button, .st-key-app-header [data-testid="stPopover"] button {{ background:var(--surface2); border:1px solid var(--border); color:var(--text); border-radius:6px; min-height:38px; font-size:14px; font-weight:600; box-shadow:none; }}
.st-key-app-header .stButton button:hover, .st-key-app-header [data-testid="stPopover"] button:hover {{ border-color:var(--accent); color:var(--accent); }}
.st-key-app-header .stButton button p, .st-key-app-header [data-testid="stPopover"] button p {{ font-size:14px; font-weight:600; }}

/* ---------- page identity ---------- */
.cs-eyebrow {{ font-size:12px; font-weight:700; letter-spacing:.14em; color:var(--accent); text-transform:uppercase; margin-top:4px; }}
.cs-title {{ font-size:28px; font-weight:750; line-height:1.15; color:var(--text); margin:2px 0 0; }}
.cs-sub {{ font-size:14px; color:var(--muted); margin:2px 0 0; }}

/* ---------- panels, KPIs ---------- */
.st-key-panel, [class*="st-key-panel-"] {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:12px 16px 12px; box-shadow:var(--shadow); }}
.cs-panel-title {{ font-size:15px; font-weight:700; letter-spacing:.08em; color:var(--text); text-transform:uppercase; margin:0 0 4px; }}
.cs-panel-note {{ font-size:12px; color:var(--muted); margin:-2px 0 4px; }}
.cs-kpi {{ background:var(--surface); border:1px solid var(--border); border-left:4px solid var(--kpi-accent, var(--accent)); border-radius:8px; padding:12px 16px; height:104px; display:flex; flex-direction:column; justify-content:center; box-shadow:var(--shadow); }}
.cs-kpi-label {{ font-size:12px; font-weight:700; letter-spacing:.1em; color:var(--muted); text-transform:uppercase; }}
.cs-kpi-value {{ font-size:32px; font-weight:750; line-height:1.15; color:var(--text); font-variant-numeric:tabular-nums; }}
.cs-kpi-support {{ font-size:13px; color:var(--muted); }}
.cs-strip {{ display:flex; flex-wrap:wrap; gap:8px 16px; align-items:center; background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:8px 16px; font-size:13px; color:var(--text); }}
.cs-strip span {{ display:inline-flex; align-items:center; gap:8px; font-weight:600; }}
.cs-strip em {{ font-style:normal; color:var(--muted); font-weight:500; }}

/* ---------- severity pills + tables ---------- */
.cs-pill {{ display:inline-block; font-size:12px; font-weight:700; letter-spacing:.06em; padding:2px 8px; border-radius:4px; text-transform:uppercase; color:var(--pill); background:var(--pill-soft); border:1px solid var(--pill); }}
.cs-pill.critical {{ --pill:var(--critical); --pill-soft:var(--critical-soft); }} .cs-pill.high {{ --pill:var(--high); --pill-soft:var(--high-soft); }}
.cs-pill.medium {{ --pill:var(--medium); --pill-soft:var(--medium-soft); }} .cs-pill.low {{ --pill:var(--low); --pill-soft:var(--low-soft); }}
.cs-pill.neutral {{ --pill:var(--muted); --pill-soft:var(--surface2); }} .cs-pill.accent {{ --pill:var(--accent); --pill-soft:var(--accent-soft); }}
.cs-table-wrap {{ overflow-x:auto; border:1px solid var(--border); border-radius:6px; }}
table.cs-table {{ width:100%; border-collapse:collapse; font-size:13px; color:var(--text); }}
table.cs-table th {{ text-align:left; font-size:12px; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); background:var(--surface2); padding:8px 12px; border-bottom:1px solid var(--border); white-space:nowrap; }}
table.cs-table td {{ padding:8px 12px; border-bottom:1px solid var(--border); vertical-align:top; max-width:420px; overflow:hidden; text-overflow:ellipsis; }}
table.cs-table tr:last-child td {{ border-bottom:0; }}
table.cs-table tr:hover td {{ background:var(--surface2); }}
.cs-mono {{ font-family:var(--mono); font-size:12px; }}
.cs-empty {{ text-align:center; padding:24px 16px; color:var(--muted); }}
.cs-empty b {{ display:block; font-size:15px; letter-spacing:.1em; color:var(--text); margin-bottom:4px; }}
.cs-rowhead, .cs-row {{ font-size:13px; }}
.cs-rowhead {{ font-size:12px; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); font-weight:700; padding:4px 0; border-bottom:1px solid var(--border); }}
[class*="st-key-alertrow-"] {{ border-bottom:1px solid var(--border); padding:2px 0; }}
[class*="st-key-alertrow-"] [data-testid="stHorizontalBlock"] {{ align-items:center; gap:8px; }}
[class*="st-key-alertrow-"] .stButton button {{ background:transparent; border:0; padding:0; min-height:28px; justify-content:flex-start; text-align:left; box-shadow:none; color:var(--accent); font-size:13px; }}
[class*="st-key-alertrow-"] .stButton button, [class*="st-key-alertrow-"] .stButton button > div {{ justify-content:flex-start !important; text-align:left !important; }}
[class*="st-key-alertrow-"] .stButton button p {{ text-align:left !important; font-size:13px; font-weight:600; color:var(--accent); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
[class*="st-key-alertrow-"]:hover {{ background:var(--surface2); }}

/* ---------- notification banner ---------- */
.st-key-crit-banner {{ background:var(--critical-soft); border:1px solid var(--critical); border-left:6px solid var(--critical); border-radius:8px; padding:12px 16px; }}
.cs-banner-title {{ font-size:15px; font-weight:800; letter-spacing:.1em; color:var(--critical); }}
.cs-banner-body {{ font-size:14px; color:var(--text); }}

/* ---------- pipeline tracker ---------- */
.cs-pipe {{ display:flex; flex-wrap:wrap; gap:4px; align-items:center; }}
.cs-step {{ font-size:12px; font-weight:700; letter-spacing:.06em; padding:8px 12px; border-radius:6px; border:1px solid var(--border); background:var(--surface2); color:var(--muted); }}
.cs-step.running {{ border-color:var(--accent); color:var(--accent); background:var(--accent-soft); }}
.cs-step.done {{ border-color:var(--low); color:var(--low); background:var(--low-soft); }}
.cs-step.failed {{ border-color:var(--critical); color:var(--critical); background:var(--critical-soft); }}
.cs-arrow {{ color:var(--muted); font-size:14px; }}

/* ---------- Streamlit widgets in both themes ---------- */
.stButton button, [data-testid="stDownloadButton"] button {{ background:var(--surface); color:var(--text); border:1px solid var(--border2); border-radius:6px; font-size:14px; font-weight:600; min-height:36px; }}
.stButton button:hover, [data-testid="stDownloadButton"] button:hover {{ border-color:var(--accent); color:var(--accent); }}
.stButton button:focus-visible, [data-testid="stDownloadButton"] button:focus-visible, input:focus-visible {{ outline:2px solid var(--accent) !important; outline-offset:1px; }}
.stButton button[kind="primary"], [data-testid="stBaseButton-primary"] {{ background:var(--accent) !important; color:var(--accent-text) !important; border-color:var(--accent) !important; }}
.stButton button[kind="primary"] p {{ color:var(--accent-text) !important; }}
.stButton button:disabled {{ opacity:.5; }}
[data-baseweb="input"], [data-baseweb="base-input"], [data-baseweb="select"] > div, [data-baseweb="textarea"], [data-testid="stTextInputRootElement"], [data-testid="stNumberInputContainer"] {{ background:var(--surface) !important; border-color:var(--border2) !important; color:var(--text) !important; }}
input, textarea {{ color:var(--text) !important; background:transparent !important; -webkit-text-fill-color:var(--text); font-size:14px !important; }}
[data-baseweb="select"] > div, [data-baseweb="select"] > div > div, [data-baseweb="select"] div[value], [data-baseweb="select"] div[data-baseweb] {{ background-color:var(--surface) !important; }}
[data-testid="stSelectbox"] div:has(> input), [data-testid="stMultiSelect"] div:has(> input), [data-testid="stSelectbox"] div:has(> div > input), [data-testid="stMultiSelect"] div:has(> div > input),
[data-testid="stDateInput"] div:has(> input), [data-testid="stTextInput"] div:has(> input), [data-testid="stNumberInput"] div:has(> input) {{ background-color:var(--surface) !important; }}
[data-testid="stSelectbox"] div:not([data-testid="stWidgetLabel"]) *, [data-testid="stMultiSelect"] div:not([data-testid="stWidgetLabel"]) * {{ color:var(--text); }}
[data-testid="stSelectbox"] svg, [data-testid="stMultiSelect"] svg {{ fill:var(--muted) !important; color:var(--muted) !important; }}
[data-baseweb="select"] *, [data-baseweb="tag"] {{ color:var(--text) !important; }}
[data-baseweb="tag"] {{ background:var(--accent-soft) !important; }}
[data-baseweb="select"] svg {{ fill:var(--muted) !important; }}
input::placeholder, [data-baseweb="select"] [class*="placeholder"] {{ color:var(--muted) !important; -webkit-text-fill-color:var(--muted) !important; opacity:1; }}
[data-testid="stDateInput"] input, [data-baseweb="calendar"], [data-baseweb="calendar"] * {{ background:var(--surface) !important; color:var(--text) !important; }}
[data-baseweb="popover"] > div, [data-baseweb="menu"], [data-baseweb="popover"] ul {{ background:var(--surface) !important; color:var(--text) !important; border:1px solid var(--border); }}
[data-baseweb="menu"] li:hover, [role="option"]:hover {{ background:var(--surface2) !important; }}
[data-testid="stPopoverBody"] {{ background:var(--surface) !important; border:1px solid var(--border) !important; color:var(--text); min-width:420px; }}
label, [data-testid="stWidgetLabel"] p, [data-testid="stWidgetLabel"] {{ color:var(--muted) !important; font-size:13px !important; font-weight:600; }}
[data-testid="stFileUploaderDropzone"] {{ background:var(--surface2) !important; border:1.5px dashed var(--border2) !important; border-radius:8px; color:var(--text); }}
[data-testid="stFileUploaderDropzone"] * {{ color:var(--muted) !important; }}
[data-testid="stFileUploaderDropzone"] button {{ color:var(--text) !important; }}
[data-testid="stSegmentedControl"] button, [data-testid="stBaseButton-segmented_control"], [data-testid="stBaseButton-pills"] {{ background:var(--surface) !important; color:var(--muted) !important; border:1px solid var(--border2) !important; font-size:14px; font-weight:600; }}
[data-testid="stBaseButton-segmented_controlActive"], [data-testid="stBaseButton-pillsActive"] {{ background:var(--accent-soft) !important; color:var(--accent) !important; border-color:var(--accent) !important; }}
[data-testid="stSegmentedControl"] p, [data-testid="stBaseButton-pills"] p {{ font-size:14px; }}
[data-testid="stExpander"] {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; }}
[data-testid="stExpander"] summary, [data-testid="stExpander"] p {{ color:var(--text); }}
[data-testid="stCode"], pre, code {{ background:var(--surface2) !important; color:var(--text) !important; font-family:var(--mono) !important; font-size:12px !important; }}
[data-testid="stAlert"] {{ background:var(--surface2); border:1px solid var(--border); color:var(--text); border-radius:8px; }}
[data-testid="stToast"] {{ background:var(--surface) !important; color:var(--text) !important; border:1px solid var(--critical); }}
[data-testid="stSlider"] [role="slider"] {{ background:var(--accent) !important; }}
[data-testid="stMetricValue"] {{ color:var(--text); }}
[data-testid="stPlotlyChart"] {{ background:transparent; }}
@media (max-width:1100px) {{ .cs-status {{ gap:12px; font-size:13px; }} .cs-brand-name {{ font-size:22px; }} }}
@media (max-width:900px) {{
  .st-key-app-nav .stButton button, .st-key-app-nav .stButton button p {{ font-size:14px; }}
  .cs-status span:not(.cs-dot) {{ font-size:12px; }}
  section.main .block-container, .stMainBlockContainer {{ padding-left:12px !important; padding-right:12px !important; }}
}}
@media (max-width:700px) {{
  .st-key-app-nav [data-testid="stHorizontalBlock"] {{ overflow-x:auto; flex-wrap:nowrap; }}
  .st-key-app-nav [data-testid="stColumn"] {{ min-width:96px; }}
  .st-key-app-header [data-testid="stHorizontalBlock"] {{ flex-wrap:wrap; }}
}}
@media (max-height:800px) {{ .cs-kpi {{ padding-top:10px; padding-bottom:10px; }} }}
</style>
"""
