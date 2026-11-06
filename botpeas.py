import requests
import datetime
import pathlib
import json
import os
import yaml
import vulners
import time
import re

from os.path import join
from enum import Enum
from discord import Webhook, RequestsWebhookAdapter
from dotenv import load_dotenv

load_dotenv()

CVES_JSON_PATH = join(pathlib.Path(__file__).parent.absolute(), "output/botpeas.json")
LAST_NEW_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
LAST_MODIFIED_CVE = datetime.datetime.now() - datetime.timedelta(days=1)
TIME_FORMAT = "%Y-%m-%dT%H:%M:%S"

KEYWORDS_CONFIG_PATH = join(pathlib.Path(__file__).parent.absolute(), "config/botpeas.yaml")
ALL_VALID = False
DESCRIPTION_KEYWORDS_I = []
DESCRIPTION_KEYWORDS = []
PRODUCT_KEYWORDS_I = []
PRODUCT_KEYWORDS = []
MIN_CVSS_SCORE = 7.0
INCLUDE_UNSCORED = False
IGNORE_REJECTED = True
NOTIFY_MODIFIED = False
MATCH_MODE = "OR"
NVD_API_KEY = ""
ONLY_ACTIONABLE = True
ACTIONABLE_MIN_CVSS = 9.0
ACTIONABLE_VECTORS = ["NETWORK"]
MODIFIED_ONLY_IF_EXPLOITED = False
EXCLUDE_DESCRIPTION_KEYWORDS_I = []
DESCRIPTION_MATCH_CHARS = 300


class Time_Type(Enum):
    PUBLISHED = "Published"
    LAST_MODIFIED = "last-modified"


################## LOAD CONFIGURATIONS ####################

def is_cvss_valid(cvss_val) -> bool:
    ''' Check if the CVSS score meets the minimum threshold '''
    if cvss_val is None or cvss_val == "N/A" or cvss_val == "":
        return INCLUDE_UNSCORED
    try:
        score = float(cvss_val)
        return score >= MIN_CVSS_SCORE
    except (ValueError, TypeError):
        return INCLUDE_UNSCORED


def load_keywords():
    ''' Load keywords and filtering options from config file '''

    global ALL_VALID
    global DESCRIPTION_KEYWORDS_I, DESCRIPTION_KEYWORDS
    global PRODUCT_KEYWORDS_I, PRODUCT_KEYWORDS
    global MIN_CVSS_SCORE, INCLUDE_UNSCORED, IGNORE_REJECTED, NOTIFY_MODIFIED, MATCH_MODE, NVD_API_KEY

    with open(KEYWORDS_CONFIG_PATH, 'r') as yaml_file:
        keywords_config = yaml.safe_load(yaml_file) or {}
        print(f"Loaded config: {keywords_config}")
        NVD_API_KEY = str(keywords_config.get("NVD_API_KEY", "") or "").strip()
        key_detected = bool(os.getenv("NVD_API_KEY") or NVD_API_KEY)
        ALL_VALID = keywords_config.get("ALL_VALID", False)
        DESCRIPTION_KEYWORDS_I = keywords_config.get("DESCRIPTION_KEYWORDS_I") or []
        DESCRIPTION_KEYWORDS = keywords_config.get("DESCRIPTION_KEYWORDS") or []
        PRODUCT_KEYWORDS_I = keywords_config.get("PRODUCT_KEYWORDS_I") or []
        PRODUCT_KEYWORDS = keywords_config.get("PRODUCT_KEYWORDS") or []
        MIN_CVSS_SCORE = float(keywords_config.get("MIN_CVSS_SCORE", 0.0))
        INCLUDE_UNSCORED = bool(keywords_config.get("INCLUDE_UNSCORED", False))
        IGNORE_REJECTED = bool(keywords_config.get("IGNORE_REJECTED", True))
        NOTIFY_MODIFIED = bool(keywords_config.get("NOTIFY_MODIFIED", False))
        MATCH_MODE = str(keywords_config.get("MATCH_MODE", "OR")).upper()
        ONLY_ACTIONABLE = bool(keywords_config.get("ONLY_ACTIONABLE", True))
        ACTIONABLE_MIN_CVSS = float(keywords_config.get("ACTIONABLE_MIN_CVSS", 9.0))
        ACTIONABLE_VECTORS = [v.upper() for v in (keywords_config.get("ACTIONABLE_VECTORS") or [])]
        MODIFIED_ONLY_IF_EXPLOITED = bool(keywords_config.get("MODIFIED_ONLY_IF_EXPLOITED", True))
        EXCLUDE_DESCRIPTION_KEYWORDS_I = keywords_config.get("EXCLUDE_DESCRIPTION_KEYWORDS_I") or []
        DESCRIPTION_MATCH_CHARS = int(keywords_config.get("DESCRIPTION_MATCH_CHARS", 300))


def load_lasttimes():
    ''' Load lasttimes from json file '''

    global LAST_NEW_CVE, LAST_MODIFIED_CVE

    try:
        with open(CVES_JSON_PATH, 'r') as json_file:
            cves_time = json.load(json_file)
            LAST_NEW_CVE = datetime.datetime.strptime(cves_time["LAST_NEW_CVE"], TIME_FORMAT)
            LAST_MODIFIED_CVE = datetime.datetime.strptime(cves_time["LAST_MODIFIED_CVE"], TIME_FORMAT)

    except Exception as e: #If error, just keep the fault date (today - 1 day)
        print(f"ERROR, using default last times.\n{e}")
        pass

    print(f"Last new cve: {LAST_NEW_CVE}")
    print(f"Last modified cve: {LAST_MODIFIED_CVE}")


def update_lasttimes():
    ''' Save lasttimes in json file '''

    with open(CVES_JSON_PATH, 'w') as json_file:
        json.dump({
            "LAST_NEW_CVE": LAST_NEW_CVE.strftime(TIME_FORMAT),
            "LAST_MODIFIED_CVE": LAST_MODIFIED_CVE.strftime(TIME_FORMAT),
        }, json_file)



################## SEARCH CVES ####################
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def parse_cve_time(time_str: str) -> datetime.datetime:
    ''' Parse various time formats returned by CVE APIs into naive UTC datetime '''
    if not time_str:
        return datetime.datetime.min
    try:
        dt = datetime.datetime.fromisoformat(time_str)
        if dt.tzinfo is not None:
            dt = dt.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return dt
    except Exception:
        for fmt in (TIME_FORMAT, "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
            try:
                return datetime.datetime.strptime(time_str, fmt)
            except ValueError:
                pass
        return datetime.datetime.min

def short_cpe(c: str) -> str:
    ''' cpe:2.3:o:linux:linux_kernel:6.1:*:... -> "linux linux_kernel" '''
    parts = c.split(":")
    return f"{parts[3]} {parts[4]}" if c.startswith("cpe:2.3:") and len(parts) > 4 else c

def normalize_nvd_cve(item: dict) -> dict:
    ''' Normalize NVD 2.0 CVE format to the dict structure expected by BotPEASS '''
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")

    # Description / Summary
    descriptions = cve.get("descriptions", [])
    summary = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    if not summary and descriptions:
        summary = descriptions[0].get("value", "")

    # CVSS Score
    metrics = cve.get("metrics", {})
    cvss, vector = "N/A", ""
    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        metric_list = metrics.get(metric_key, [])
        if metric_list and isinstance(metric_list, list):
            cvss_data = metric_list[0].get("cvssData", {})
            base_score = cvss_data.get("baseScore")
            if base_score is not None:
                cvss = base_score
                vector = str(cvss_data.get("attackVector") or cvss_data.get("accessVector") or "").upper()
                break

    # Published & Last Modified dates
    published = cve.get("published", "")
    last_modified = cve.get("lastModified", published)

    # Vulnerable configuration / products
    vulnerable_config = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                crit = cpe.get("criteria")
                if crit:
                    vulnerable_config.append(short_cpe(crit))

    for aff in cve.get("affected", []):
        for aff_data in aff.get("affectedData", []):
            vendor = aff_data.get("vendor", "")
            product = aff_data.get("product", "")
            name = f"{vendor} {product}".strip()
            if name:
                vulnerable_config.append(name)

    # References
    references = [ref.get("url", "") for ref in cve.get("references", []) if ref.get("url")]

    return {
        "id": cve_id,
        "summary": summary,
        "cvss": cvss,
        "vector": vector,
        "kev": bool(cve.get("cisaExploitAdd")),
        "Published": published,
        "last-modified": last_modified,
        "vulnerable_configuration": list(dict.fromkeys(vulnerable_config)),  # dedupe
        "references": references,
    }

NVD_MAX_RANGE_DAYS = 119  # NVD rejects date ranges longer than 120 days

def utc_now_naive() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

def get_cves(tt_filter: Time_Type, since: datetime.datetime) -> list:
    ''' Retrieve and normalize CVEs from NVD API 2.0 since a given naive-UTC time '''
    end = utc_now_naive()
    start = since
    if end - start > datetime.timedelta(days=NVD_MAX_RANGE_DAYS):
        start = end - datetime.timedelta(days=NVD_MAX_RANGE_DAYS)

    headers = {"User-Agent": "BotPEASS-CVE-Monitor"}
    nvd_api_key = os.getenv("NVD_API_KEY") or NVD_API_KEY
    if nvd_api_key:
        headers["apiKey"] = nvd_api_key.strip()

    fmt = "%Y-%m-%dT%H:%M:%S.000"
    if tt_filter == Time_Type.PUBLISHED:
        params = {"pubStartDate": start.strftime(fmt), "pubEndDate": end.strftime(fmt)}
    else:
        params = {"lastModStartDate": start.strftime(fmt), "lastModEndDate": end.strftime(fmt)}

    page_size = 2000
    start_index = 0
    results = []

    try:
        while True:
            params["resultsPerPage"] = page_size
            params["startIndex"] = start_index
            r = requests.get(NVD_URL, headers=headers, params=params, timeout=60)
            r.raise_for_status()
            data = r.json()
            results.extend(normalize_nvd_cve(i) for i in data.get("vulnerabilities", []))

            start_index += data.get("resultsPerPage", page_size)
            if start_index >= data.get("totalResults", 0):
                break
            time.sleep(0.7 if nvd_api_key else 6)  # respect rate limits
    except Exception as e:
        print(f"Error fetching CVEs from NVD: {e}")

    return results


def get_new_cves() -> list:
    global LAST_NEW_CVE
    cves = get_cves(Time_Type.PUBLISHED, LAST_NEW_CVE)
    filtered_cves, new_last_time = filter_cves(cves, LAST_NEW_CVE, Time_Type.PUBLISHED)
    LAST_NEW_CVE = new_last_time
    return filtered_cves


def get_modified_cves() -> list:
    global LAST_MODIFIED_CVE
    cves = get_cves(Time_Type.LAST_MODIFIED, LAST_MODIFIED_CVE)
    filtered_cves, new_last_time = filter_cves(cves, LAST_MODIFIED_CVE, Time_Type.LAST_MODIFIED)
    LAST_MODIFIED_CVE = new_last_time
    return filtered_cves

def is_excluded(summary: str) -> bool:
    return any(w.lower() in summary.lower() for w in EXCLUDE_DESCRIPTION_KEYWORDS_I)


def is_actionable(cve: dict) -> bool:
    ''' Exploited in the wild, or critical and reachable the way you care about '''
    if cve.get("kev"):
        return True
    try:
        score = float(cve.get("cvss"))
    except (TypeError, ValueError):
        return False
    vector_ok = not ACTIONABLE_VECTORS or cve.get("vector") in ACTIONABLE_VECTORS
    return score >= ACTIONABLE_MIN_CVSS and vector_ok

def filter_cves(cves: list, last_time: datetime.datetime, tt_filter: Time_Type) -> list:
    ''' Filter by time, score, and keywords the given list of CVEs '''

    filtered_cves = []
    new_last_time = last_time

    for cve in cves:
        cve_time = parse_cve_time(cve[tt_filter.value])
        if cve_time > new_last_time:
            new_last_time = cve_time

        if cve_time > last_time:
            summary = cve.get("summary", "")

            if IGNORE_REJECTED and ("** REJECT **" in summary or "** DISPUTED **" in summary):
                continue
            if not is_cvss_valid(cve.get("cvss")):
                continue
            if is_excluded(summary):
                continue
            if ONLY_ACTIONABLE and not is_actionable(cve):
                continue

            # Check keywords
            if ALL_VALID:
                cve["matched"] = ["ALL_VALID"]
                filtered_cves.append(cve)
                continue

            summ_hits, prod_hits = find_matches(cve)
            has_summ, has_prod = bool(summ_hits), bool(prod_hits)

            if MATCH_MODE == "AND":
                both_defined = bool(DESCRIPTION_KEYWORDS or DESCRIPTION_KEYWORDS_I) and bool(PRODUCT_KEYWORDS or PRODUCT_KEYWORDS_I)
                keep = (has_summ and has_prod) if both_defined else (has_summ or has_prod)
            else:
                keep = has_summ or has_prod

            if keep:
                cve["matched"] = summ_hits + prod_hits
                filtered_cves.append(cve)

    return filtered_cves, new_last_time

def kw_in(text: str, kw: str, case_sensitive: bool = False) -> bool:
    ''' Whole-word match; '_' counts as a separator so "docker" hits "docker_desktop" '''
    kw = kw.strip()
    if not kw:
        return False
    flags = 0 if case_sensitive else re.IGNORECASE
    return re.search(rf"(?<![A-Za-z0-9]){re.escape(kw)}(?![A-Za-z0-9])", text, flags) is not None


def find_matches(cve: dict):
    ''' Return (summary_hits, product_hits) and remember which products matched '''
    summary = cve.get("summary", "")
    scope = summary[:DESCRIPTION_MATCH_CHARS] if DESCRIPTION_MATCH_CHARS else summary

    summ_hits = [f"summary: {w}" for w in DESCRIPTION_KEYWORDS if kw_in(scope, w, True)]
    summ_hits += [f"summary: {w}" for w in DESCRIPTION_KEYWORDS_I if kw_in(scope, w)]

    prod_hits, matched_products = [], []
    for p in cve.get("vulnerable_configuration", []):
        for w in PRODUCT_KEYWORDS:
            if kw_in(p, w, True):
                prod_hits.append(f"product: {w} ({p})")
                matched_products.append(p)
        for w in PRODUCT_KEYWORDS_I:
            if kw_in(p, w):
                prod_hits.append(f"product: {w} ({p})")
                matched_products.append(p)

    cve["matched_products"] = list(dict.fromkeys(matched_products))
    return list(dict.fromkeys(summ_hits)), list(dict.fromkeys(prod_hits))

def search_exploits(cve: str) -> list:
    ''' Given a CVE it will search for public exploits to abuse it '''
    vulners_api_key = os.getenv('VULNERS_API_KEY')
    
    if vulners_api_key:
        vulners_api = vulners.Vulners(api_key=vulners_api_key)
        cve_data = vulners_api.searchExploit(cve)
        return [v['vhref'] for v in cve_data]
    
    return []
    
def short_summary(summary: str, limit: int = 300) -> str:
    ''' Trim at a sentence (or word) boundary instead of mid-word '''
    marker = "has been resolved:"
    if marker in summary:
        lines = [l.strip() for l in summary.split(marker, 1)[1].splitlines() if l.strip()]
        summary = "Linux kernel: " + lines[0] if lines else summary
    summary = " ".join(summary.split())
    if len(summary) <= limit:
        return summary
    cut = summary[:limit]
    end = cut.rfind(". ")
    if end > limit * 0.5:
        return cut[:end + 1]
    return cut.rsplit(" ", 1)[0] + "…"


def product_line(cve: dict, n: int = 3) -> str:
    ''' Matched products first, then the rest, e.g. "canonical ubuntu_linux, isc bind +12 more" '''
    allp = cve.get("vulnerable_configuration", [])
    ordered = list(dict.fromkeys(cve.get("matched_products", []) + allp))
    if not ordered:
        return "unknown product"
    shown = ", ".join(md_safe(p) for p in ordered[:n])
    extra = len(ordered) - n
    return shown + (f" +{extra} more" if extra > 0 else "")


def _build_message(icon: str, cve: dict) -> str:
    flag = "  🔥 *Exploited*" if cve.get("kev") else ""
    message = f"{icon} *{md_safe(cve['id'])}* — {product_line(cve)}\n"
    message += f"CVSS {cve['cvss']}{flag}\n"
    message += md_safe(short_summary(cve.get("summary", ""))) + "\n"
    matched = cve.get("matched", [])
    if matched:
        message += "🎯 " + md_safe("; ".join(matched[:3]))
    return message + "\n"

def generate_new_cve_message(cve_data: dict) -> str:
    return _build_message("🚨", cve_data)

def generate_modified_cve_message(cve_data: dict) -> str:
    return _build_message("🔄", cve_data)

def generate_public_expls_message(public_expls: list) -> str:
    ''' Given the list of public exploits, generate the message '''

    message = ""

    if public_expls:
        message = "😈  *Public Exploits* (_limit 20_)  😈\n" + "\n".join(public_expls[:20])

    return message


#################### SEND MESSAGES #########################

def send_slack_mesage(message: str, public_expls_msg: str):
    ''' Send a message to the slack group '''

    slack_url = os.getenv('SLACK_WEBHOOK')

    if not slack_url:
        return
    
    json_params = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn", 
                    "text": message
                }
            },
            {
                "type": "divider"
            }
        ]
    }

    if public_expls_msg:
        json_params["blocks"].append({
                "type": "section",
                "text": {
                    "type": "mrkdwn", 
                    "text": public_expls_msg
                }
        })

    requests.post(slack_url, json=json_params)

def escape_md_v2(text: str) -> str:
    ''' Escape all MarkdownV2 special chars except '*' (used for our bold markers) '''
    return re.sub(r'([_\[\]()~`>#+\-=|{}.!\\])', r'\\\1', text)

def md_safe(text: str) -> str:
    ''' Remove '*' from dynamic content so it can't unbalance bold markers '''
    return str(text).replace("*", "")

def send_telegram_message(message: str, public_expls_msg: str):
    ''' Send a message to the telegram group '''

    telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
    telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')

    if not telegram_bot_token:
        print("TELEGRAM_BOT_TOKEN wasn't configured in the secrets!")
        return

    if not telegram_chat_id:
        print("TELEGRAM_CHAT_ID wasn't configured in the secrets!")
        return

    if public_expls_msg:
        message = message + "\n" + public_expls_msg

    api_url = f"https://api.telegram.org/bot{telegram_bot_token}/sendMessage"

    # Attempt 1: MarkdownV2
    r = requests.post(api_url, data={
        "chat_id": telegram_chat_id,
        "text": escape_md_v2(message),
        "parse_mode": "MarkdownV2",
    }, timeout=30)
            
def send_discord_message(message: str, public_expls_msg: str):
    ''' Send a message to the discord channel webhook '''

    discord_webhok_url = os.getenv('DISCORD_WEBHOOK_URL')

    if not discord_webhok_url:
        return
    
    if public_expls_msg:
        message = message + "\n" + public_expls_msg

    message = message.replace("(", "\\(").replace(")", "\\)").replace("_", "").replace("[","\\[").replace("]","\\]").replace("{","\\{").replace("}","\\}").replace("=","\\=")
    webhook = Webhook.from_url(discord_webhok_url, adapter=RequestsWebhookAdapter())
    if public_expls_msg:
        message = message + "\n" + public_expls_msg
    
    webhook.send(message)

def send_pushover_message(message: str, public_expls_msg: str):
    ''' Send a message to the pushover device '''

    pushover_device_name = os.getenv('PUSHOVER_DEVICE_NAME')
    pushover_user_key = os.getenv('PUSHOVER_USER_KEY')
    pushover_token = os.getenv('PUSHOVER_TOKEN') 

    if not pushover_device_name:
        return 
    if not pushover_user_key:
        return
    if not pushover_token:
        return
    if public_expls_msg:
        message = message + "\n" + public_expls_msg

    data = { "token": pushover_token, "user": pushover_user_key, "message": message , "device": pushover_device_name}
    try:
        r = requests.post("https://api.pushover.net/1/messages.json", data = data)
    except Exception as e:
        print("ERROR SENDING TO PUSHOVER: "+ message.split("\n")[0] +message)


def send_ntfy_message(message: str, public_expls_msg: str):
    ''' Send a message to the ntfy.sh topic '''

    ntfy_url = os.getenv('NTFY_URL')
    ntfy_topic = os.getenv('NTFY_TOPIC')
    ntfy_auth = os.getenv('NTFY_AUTH')

    if not ntfy_url:
        return

    if not ntfy_topic:
        return

    # Combine message and public exploits message if exists
    if public_expls_msg:
        message = message + "\n" + public_expls_msg

    full_ntfy_url = f"{ntfy_url}/{ntfy_topic}"

    headers = {
        "Title": "New CVE Alert",
        "Priority": "high",
    }

    if ntfy_auth:
        headers["Authorization"] = ntfy_auth

    print(full_ntfy_url)
    response = requests.post(full_ntfy_url, data=message.encode('utf-8'), headers=headers)

    if response.status_code == 200:
        print(f"Notification sent to ntfy.sh topic: {ntfy_topic}")
    else:
        print(f"Failed to send notification to ntfy.sh. Status code: {response.status_code}, Response: {response.text}")

#################### MAIN #########################

def main():
    #Load configured keywords
    load_keywords()

    #Start loading time of last checked ones
    load_lasttimes()

    #Find a publish new CVEs
    new_cves = get_new_cves()

    new_cves_ids = [ncve['id'] for ncve in new_cves]
    print(f"New CVEs discovered: {new_cves_ids}")

    for new_cve in new_cves:
        public_exploits = search_exploits(new_cve['id'])
        cve_message = generate_new_cve_message(new_cve)
        public_expls_msg = generate_public_expls_message(public_exploits)
        send_slack_mesage(cve_message, public_expls_msg)
        send_telegram_message(cve_message, public_expls_msg)
        send_discord_message(cve_message, public_expls_msg)
        send_pushover_message(cve_message, public_expls_msg)
        send_ntfy_message(cve_message, public_expls_msg)

    #Find and publish modified CVEs
    global LAST_MODIFIED_CVE
    if NOTIFY_MODIFIED:
        # Sleep to respect NVD API rate limits (5 requests / 30 seconds without API key)
        time.sleep(6)
        modified_cves = get_modified_cves()

        modified_cves = [mcve for mcve in modified_cves if not mcve['id'] in new_cves_ids]
        modified_cves_ids = [mcve['id'] for mcve in modified_cves]
        if MODIFIED_ONLY_IF_EXPLOITED:
            modified_cves = [m for m in modified_cves if m.get("kev")]

        print(f"Modified CVEs discovered: {modified_cves_ids}")

        for modified_cve in modified_cves:
            public_exploits = search_exploits(modified_cve['id'])
            cve_message = generate_modified_cve_message(modified_cve)
            public_expls_msg = generate_public_expls_message(public_exploits)
            send_slack_mesage(cve_message, public_expls_msg)
            send_telegram_message(cve_message, public_expls_msg)
            send_discord_message(cve_message, public_expls_msg)
            send_pushover_message(cve_message, public_expls_msg)
            send_ntfy_message(cve_message, public_expls_msg)
    else:
        print("Skipping modified CVEs notifications (NOTIFY_MODIFIED is disabled)")
        LAST_MODIFIED_CVE = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)

    #Update last times
    update_lasttimes()

    # call healthcheck
    try:
        requests.get('https://hc-ping.com/cqasv55yxlwxoretrhbg8w/cve-notification', timeout=10)
    except Exception as e:
        print(f"Healthcheck ping failed: {e}")


if __name__ == "__main__":
    main()
