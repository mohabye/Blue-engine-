import requests
import urllib.parse
import json
from bs4 import BeautifulSoup
from fuzzywuzzy import fuzz

FUZZY_THRESHOLD = 40
MAX_RESULTS_TO_SHOW = 10

def main():
    tech = input("Enter a cybersecurity technique: ").strip().lower()
    print(f"\n\033[94m🔍 Searching for partial matches of: '{tech}' (threshold={FUZZY_THRESHOLD})\033[0m\n")

    mitre_candidates    = fetch_mitre_tech_links(tech)
    reddit_candidates   = fetch_reddit_post_links(tech)
    elastic_candidates  = fetch_elastic_security_links(tech)
    medium_candidates   = fetch_medium_articles(tech)
    ired_candidates     = fetch_ired_team_links(tech)
    wazuh_candidates    = fetch_wazuh_blog_links(tech)
    root_x_candidates   = fetch_root_x_blog_links(tech)
    sh3ll_candidates    = fetch_sh3ll_blog_links(tech)

    print("\033[94m🌐 MITRE ATT&CK Results:\033[0m")
    if mitre_candidates and mitre_candidates[0][0] > 0:
        for score, link in mitre_candidates[:MAX_RESULTS_TO_SHOW]:
            print(f"   [score={score}] \033[92m{link}\033[0m")
    else:
        print("   No MITRE matches found or none met threshold.")

    print("\n\033[94m🌐 Reddit (/r/netsec) Results:\033[0m")
    if reddit_candidates and reddit_candidates[0][0] > 0:
        for score, link in reddit_candidates[:MAX_RESULTS_TO_SHOW]:
            print(f"   [score={score}] \033[92m{link}\033[0m")
    else:
        print("   No relevant Reddit posts found or none met threshold.")

    print("\n\033[94m🌐 Elastic Security Docs:\033[0m")
    if elastic_candidates and elastic_candidates[0][0] > 0:
        for score, link in elastic_candidates[:MAX_RESULTS_TO_SHOW]:
            print(f"   [score={score}] \033[92m{link}\033[0m")
    else:
        print("   No relevant Elastic Security docs found or none met threshold.")

    print("\n\033[94m🌐 Medium Articles:\033[0m")
    if medium_candidates and medium_candidates[0][0] > 0:
        for score, link in medium_candidates[:MAX_RESULTS_TO_SHOW]:
            print(f"   [score={score}] \033[92m{link}\033[0m")
    else:
        print("   No relevant Medium articles found or none met threshold.")

    print("\n\033[94m🌐 iRed.Team (Homepage) Results:\033[0m")
    if ired_candidates and ired_candidates[0][0] > 0:
        for score, link in ired_candidates[:MAX_RESULTS_TO_SHOW]:
            print(f"   [score={score}] \033[92m{link}\033[0m")
    else:
        print("   No relevant iRed.Team results found or none met threshold.")

    print("\n\033[94m🌐 Wazuh Blog Results:\033[0m")
    if wazuh_candidates and wazuh_candidates[0][0] > 0:
        for score, link in wazuh_candidates[:MAX_RESULTS_TO_SHOW]:
            print(f"   [score={score}] \033[92m{link}\033[0m")
    else:
        print("   No relevant Wazuh blog results found or none met threshold.")

    print("\n\033[94m🌐 Root X Blog (Arabic) Results:\033[0m")
    if root_x_candidates and root_x_candidates[0][0] > 0:
        for score, link in root_x_candidates[:MAX_RESULTS_TO_SHOW]:
            print(f"   [score={score}] \033[92m{link}\033[0m")
    else:
        print("   No relevant Root X blog results found or none met threshold.")

    print("\n\033[94m🌐 Sh3ll (Arabic) Results:\033[0m")
    if sh3ll_candidates and sh3ll_candidates[0][0] > 0:
        for score, link in sh3ll_candidates[:MAX_RESULTS_TO_SHOW]:
            print(f"   [score={score}] \033[92m{link}\033[0m")
    else:
        print("   No relevant Sh3ll results found or none met threshold.")

def partial_match_score(query, text):
    return fuzz.partial_ratio(query, text)

def fix_mitre_id_format(technique_id):
    if '.' in technique_id:
        return technique_id.replace('.', '/', 1)
    return technique_id

def fetch_mitre_tech_links(tech):
    cti_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    try:
        resp = requests.get(cti_url, timeout=10)
        resp.raise_for_status()
    except Exception as e:
        return [(0, f"Failed to fetch MITRE CTI JSON: {e}")]
    data = resp.json()
    candidates = []
    for obj in data["objects"]:
        if obj.get("type") == "attack-pattern":
            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break
            if technique_id:
                name = obj.get("name", "")
                desc = obj.get("description", "")
                combined_text = (name + " " + desc).lower()
                score = partial_match_score(tech, combined_text)
                if score >= FUZZY_THRESHOLD:
                    fixed_id = fix_mitre_id_format(technique_id)
                    technique_url = f"https://attack.mitre.org/techniques/{fixed_id}"
                    candidates.append((score, technique_url))
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates

def fetch_reddit_post_links(tech):
    search_url = f"https://www.reddit.com/r/netsec/search/?q={urllib.parse.quote(tech)}&restrict_sr=1"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = requests.get(search_url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return [(0, f"Failed to connect to Reddit (status {resp.status_code}).")]
    except Exception as e:
        return [(0, f"Failed to connect to Reddit: {e}")]
    soup = BeautifulSoup(resp.text, "html.parser")
    posts = soup.select("a[href^='/r/netsec/comments/']")
    if not posts:
        return []
    candidates = []
    for post in posts:
        title = post.get_text(strip=True)
        url = "https://www.reddit.com" + post.get("href", "")
        score = partial_match_score(tech, title.lower())
        if score >= FUZZY_THRESHOLD:
            candidates.append((score, url))
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates

def fetch_elastic_security_links(tech):
    url = "https://www.elastic.co/guide/en/security/current/"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return [(0, f"Failed to connect to Elastic Security Docs (status {resp.status_code}).")]
    except Exception as e:
        return [(0, f"Failed to connect to Elastic Security Docs: {e}")]
    soup = BeautifulSoup(resp.text, "html.parser")
    anchors = soup.select("a")
    if not anchors:
        return []
    candidates = []
    for a in anchors:
        link_text = a.get_text(strip=True)
        link_href = a.get("href", "")
        full_link = urllib.parse.urljoin(url, link_href)
        score_text = partial_match_score(tech, link_text.lower())
        score_href = partial_match_score(tech, link_href.lower())
        score = max(score_text, score_href)
        if score >= FUZZY_THRESHOLD:
            candidates.append((score, full_link))
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates

def fetch_medium_articles(tech):
    base_url = "https://medium.com"
    search_url = f"{base_url}/search?q={urllib.parse.quote(tech)}"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = requests.get(search_url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return [(0, f"Failed to connect to Medium (status {resp.status_code}).")]
    except Exception as e:
        return [(0, f"Failed to connect to Medium: {e}")]
    soup = BeautifulSoup(resp.text, "html.parser")
    candidates = []
    headings = soup.select("h2, h3")
    for heading in headings:
        text = heading.get_text(strip=True).lower()
        parent_a = heading.find_parent("a")
        if parent_a:
            href = parent_a.get("href", "")
            if href.startswith("https://medium.com/"):
                score = partial_match_score(tech, text)
                if score >= FUZZY_THRESHOLD:
                    candidates.append((score, href))
    anchors = soup.select("a")
    for a in anchors:
        link_text = a.get_text(strip=True).lower()
        href = a.get("href", "")
        if href.startswith("https://medium.com/"):
            score_text = partial_match_score(tech, link_text)
            score_href = partial_match_score(tech, href.lower())
            score = max(score_text, score_href)
            if score >= FUZZY_THRESHOLD:
                candidates.append((score, href))
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates

def fetch_ired_team_links(tech):
    url = "https://www.ired.team/"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return [(0, f"Failed to connect to iRed.Team (status {resp.status_code}).")]
    except Exception as e:
        return [(0, f"Failed to connect to iRed.Team: {e}")]
    soup = BeautifulSoup(resp.text, "html.parser")
    anchors = soup.select("a")
    if not anchors:
        return []
    candidates = []
    for a in anchors:
        link_text = a.get_text(strip=True).lower()
        link_href = a.get("href", "")
        full_link = urllib.parse.urljoin(url, link_href)
        score_text = partial_match_score(tech, link_text)
        score_href = partial_match_score(tech, link_href.lower())
        score = max(score_text, score_href)
        if score >= FUZZY_THRESHOLD:
            candidates.append((score, full_link))
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates

def fetch_wazuh_blog_links(tech):
    url = "https://wazuh.com/blog/"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return [(0, f"Failed to connect to Wazuh blog (status {resp.status_code}).")]
    except Exception as e:
        return [(0, f"Failed to connect to Wazuh blog: {e}")]
    soup = BeautifulSoup(resp.text, "html.parser")
    anchors = soup.select("a")
    if not anchors:
        return []
    candidates = []
    for a in anchors:
        link_text = a.get_text(strip=True).lower()
        link_href = a.get("href", "")
        full_link = urllib.parse.urljoin(url, link_href)
        score_text = partial_match_score(tech, link_text)
        score_href = partial_match_score(tech, link_href.lower())
        score = max(score_text, score_href)
        if score >= FUZZY_THRESHOLD:
            candidates.append((score, full_link))
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates

def fetch_root_x_blog_links(tech):
    url = "https://root-x.dev/blog/"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return [(0, f"Failed to connect to Root X (status {resp.status_code}).")]
    except Exception as e:
        return [(0, f"Failed to connect to Root X: {e}")]
    soup = BeautifulSoup(resp.text, "html.parser")
    anchors = soup.select("a")
    if not anchors:
        return []
    candidates = []
    for a in anchors:
        link_text = a.get_text(strip=True).lower()
        link_href = a.get("href", "")
        full_link = urllib.parse.urljoin(url, link_href)
        score_text = partial_match_score(tech, link_text)
        score_href = partial_match_score(tech, link_href.lower())
        score = max(score_text, score_href)
        if score >= FUZZY_THRESHOLD:
            candidates.append((score, full_link))
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates

def fetch_sh3ll_blog_links(tech):
    url = "https://sh3ll.cloud/xf2/"
    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            return [(0, f"Failed to connect to Sh3ll (status {resp.status_code}).")]
    except Exception as e:
        return [(0, f"Failed to connect to Sh3ll: {e}")]
    soup = BeautifulSoup(resp.text, "html.parser")
    anchors = soup.select("a")
    if not anchors:
        return []
    candidates = []
    for a in anchors:
        link_text = a.get_text(strip=True).lower()
        link_href = a.get("href", "")
        full_link = urllib.parse.urljoin(url, link_href)
        score_text = partial_match_score(tech, link_text)
        score_href = partial_match_score(tech, link_href.lower())
        score = max(score_text, score_href)
        if score >= FUZZY_THRESHOLD:
            candidates.append((score, full_link))
    candidates.sort(key=lambda x: x[0], reverse=True)
    return candidates

if __name__ == "__main__":
    main()
