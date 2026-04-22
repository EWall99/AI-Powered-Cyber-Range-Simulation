import re
import requests
import sseclient
from openai import OpenAI
from urllib.parse import unquote
from collections import defaultdict

# ============================================
# CONFIGURATION
# ============================================
LM_STUDIO_URL = "YOUR_CTFD_TOKEN_HERE"
API_URL = "YOUR_API_URL_HERE"
API_KEY = "YOUR_API_KEY_HERE"
CTFD_URL = "http://YOUR_SERVER_IP:"
CTFD_TOKEN = "http://YOUR_SERVER_IP:"


BLUE_TEAM_CHALLENGES = {
    "sql": 4,
    "cmd": 5,
    "brute": 6
}
# ============================================

client = OpenAI(base_url=LM_STUDIO_URL, api_key="lm-studio")
blocked_ips = set()
scored_blocks = set()
brute_attempts = defaultdict(int)

ALL_ATTACK_PATTERNS = [
    "union select", "union+select", "or '1'='1", "or+1=1",
    "information_schema", "union", "drop table", "insert into",
    "0x", "/**/", "/*!",
    ";cat", ";ls", "| cat", "| ls", "&& cat",
    "/etc/passwd", "flag2.txt", "$(cat", "`cat",
    "../", "exec(", "sleep(", "benchmark(",
]

HEADERS = {"X-API-Key": API_KEY, "Content-Type": "application/json"}


def block_ip(ip, attack_type, reason):
    """
    Sends block request to security API instantly.
    API adds IP to blocklist and runs UFW.
    Nginx checks blocklist before every DVWA request
    so attacker is locked out on the very next request
    — existing sessions are killed at the proxy layer.
    """
    if ip in blocked_ips:
        return
    try:
        r = requests.post(
            f"{API_URL}/block",
            headers=HEADERS,
            json={"ip": ip},
            timeout=5
        )
        if r.status_code == 200:
            print(f"\n[!!!] BLOCKED {ip}")
            print(f"      Reason: {reason}")
            print(f"      Type: {attack_type}")
            blocked_ips.add(ip)
            score_block(attack_type)
        else:
            print(f"[-] Block failed: {r.text}")
    except Exception as e:
        print(f"[-] Block error: {e}")


def parse_log_line(line):
    """
    Parses Apache log lines into structured data.
    Decodes URL encoding so attack patterns are readable.
    Without decoding, %27+UNION+SELECT would never match.
    """
    match = re.match(r'(\d+\.\d+\.\d+\.\d+).*?"(\w+)\s+([^\s]+)', line)
    if match:
        path = unquote(match.group(3)).replace('+', ' ')
        return {
            "ip": match.group(1),
            "method": match.group(2),
            "path": path
        }
    return None


def detect_attack(path):
    """
    Checks request path against known attack patterns.
    Returns matched pattern or None if clean traffic.
    """
    path_lower = path.lower()
    for pattern in ALL_ATTACK_PATTERNS:
        if pattern in path_lower:
            return pattern
    return None


def get_attack_type(pattern, path):
    if any(x in pattern for x in [";", "|", "cat", "ls", "passwd", "flag2", "exec", "$(", "`"]):
        return "cmd"
    elif "brute" in path.lower():
        return "brute"
    return "sql"


def is_brute_force(parsed):
    if parsed['method'] == 'GET' and 'vulnerabilities/brute' in parsed['path']:
        return True
    return False


def ask_llm(ip, path, pattern):
    """
    Asks LM Studio to explain the attack after blocking.
    Called after block fires so LLM never delays response.
    In real security tools automated response fires first,
    analysis follows — this mirrors that approach.
    """
    try:
        response = client.chat.completions.create(
            model="local-model",
            messages=[
                {"role": "system", "content": """You are a blue team security analyst.
                 Explain detected web attacks clearly and concisely.
                 Respond ONLY in this format:
                 ATTACK TYPE: name
                 TECHNIQUE: specific technique used
                 IMPACT: what would have happened if not blocked
                 EXPLANATION: one sentence summary"""},
                {"role": "user", "content": f"""
                 Blocked IP: {ip}
                 Request: {path}
                 Pattern: {pattern}
                 Explain this attack."""}
            ]
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        return f"LLM unavailable: {e}"


def get_ctfd_nonce():
    try:
        r = requests.get(
            f"{CTFD_URL}/challenges",
            headers={"Authorization": f"Token {CTFD_TOKEN}"},
            timeout=5
        )
        nonce = re.search(r"'csrfNonce': \"(.*?)\"", r.text)
        return nonce.group(1) if nonce else ""
    except:
        return ""


def score_block(attack_type):
    """
    Submits flag to CTFd when block happens.
    Only scored once per attack type per session.
    """
    if attack_type in scored_blocks:
        return
    challenge_id = BLUE_TEAM_CHALLENGES.get(attack_type)
    if not challenge_id:
        return
    flag_map = {
        "sql": "BLUE{sql_blocked}",
        "cmd": "BLUE{cmd_blocked}",
        "brute": "BLUE{brute_blocked}"
    }
    flag = flag_map.get(attack_type)
    if not flag:
        return
    try:
        nonce = get_ctfd_nonce()
        r = requests.post(
            f"{CTFD_URL}/api/v1/challenges/attempt",
            json={"challenge_id": challenge_id, "submission": flag},
            headers={
                "Authorization": f"Token {CTFD_TOKEN}",
                "Content-Type": "application/json",
                "CSRF-Token": nonce
            },
            timeout=5
        )
        result = r.json()
        if result.get("data", {}).get("status") == "correct":
            print(f"[+] BLUE TEAM SCORED for blocking {attack_type}")
            scored_blocks.add(attack_type)
    except Exception as e:
        print(f"[-] Scoring error: {e}")


def defense_loop():
    print("=== BLUE TEAM BOT STARTING ===")

    try:
        r = requests.get(f"{API_URL}/health", headers=HEADERS, timeout=5)
        print(f"[+] Security API connected: {r.json()}")
    except:
        print(f"[-] Cannot reach security API at {API_URL}")
        return

    print("[*] Connecting to live log stream...")

    try:
        stream_response = requests.get(
            f"{API_URL}/stream",
            headers={**HEADERS, "Accept": "text/event-stream"},
            stream=True,
            timeout=None
        )
        client_sse = sseclient.SSEClient(stream_response)
        print("[*] LIVE STREAM ACTIVE — detecting attacks in real time")
        print("[*] Every request hits the detector the instant it arrives")
        print("-" * 50)

        for event in client_sse.events():
            if not event.data or event.data == "ping":
                continue

            line = event.data
            parsed = parse_log_line(line)
            if not parsed:
                continue

            ip = parsed['ip']
            path = parsed['path']

            if ip in blocked_ips:
                continue

            print(f"[>] {ip} {parsed['method']} {path[:70]}")

            # Instant block on attack pattern
            pattern = detect_attack(path)
            if pattern:
                attack_type = get_attack_type(pattern, path)
                print(f"\n[!!!] ATTACK DETECTED — blocking {ip} instantly")
                print(f"      Pattern: {pattern}")

                # Block fires immediately
                block_ip(ip, attack_type, pattern)

                # LLM explains after
                decision = ask_llm(ip, path, pattern)
                print("[*] LLM Analysis:")
                for l in decision.split('\n'):
                    print(f"    {l}")
                print("-" * 50)
                continue

            # Brute force counting
            if is_brute_force(parsed):
                brute_attempts[ip] += 1
                count = brute_attempts[ip]
                if count >= 3:
                    print(f"\n[!!!] BRUTE FORCE from {ip} — blocking after {count} attempts")
                    block_ip(ip, "brute", f"brute force after {count} attempts")
                    print("-" * 50)
                elif count % 2 == 0:
                    print(f"\n[?] Brute force from {ip} — {count} attempts")

    except KeyboardInterrupt:
        print(f"\n[*] Blue team stopped")
        print(f"[*] Blocked: {blocked_ips}")
        print(f"[*] Scored: {scored_blocks}")
    except Exception as e:
        print(f"[-] Stream error: {e}")


if __name__ == "__main__":
    defense_loop()