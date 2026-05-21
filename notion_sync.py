#!/opt/miniconda3/envs/network/bin/python
import os
import re
import json
import sys
import glob
import urllib.request
import urllib.error

# Default checklist markdown file (fallback)
DEFAULT_CHECKLIST = "kismet_siem_elk_checklist.md"
ENV_PATH = ".env"

# Directory to scan for .md files (project root)
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def choose_md_file():
    """Scans the project root for .md files and presents an interactive picker menu."""
    md_files = sorted(glob.glob(os.path.join(PROJECT_ROOT, "*.md")))
    if not md_files:
        print("[!] No .md files found in project root.")
        sys.exit(1)

    # Determine default index (the checklist file if it exists)
    default_idx = 0
    for i, f in enumerate(md_files):
        if os.path.basename(f) == DEFAULT_CHECKLIST:
            default_idx = i
            break

    print("\n📂 Chọn file Markdown để đồng bộ lên Notion:")
    print("-" * 60)
    for i, f in enumerate(md_files):
        basename = os.path.basename(f)
        marker = " ← mặc định" if i == default_idx else ""
        print(f"  [{i + 1}] {basename}{marker}")
    print("-" * 60)

    raw = input(f"Nhập số thứ tự [1-{len(md_files)}] (mặc định {default_idx + 1}): ").strip()
    if not raw:
        chosen = default_idx
    else:
        try:
            chosen = int(raw) - 1
            if chosen < 0 or chosen >= len(md_files):
                raise ValueError
        except ValueError:
            print("[!] Lựa chọn không hợp lệ. Sử dụng file mặc định.")
            chosen = default_idx

    selected = md_files[chosen]
    print(f"[*] Đã chọn: {os.path.basename(selected)}")
    return selected

def print_banner():
    print("=" * 60)
    print("      🌳 WIDS & ELK SIEM CHECKLIST NOTION SYNCHRONIZER 🌳")
    print("=" * 60)

def load_notion_config():
    """Attempts to load Notion configurations from the environment or SIEM/.env file."""
    config = {"token": "", "page_id": ""}
    
    # Check system environment variables first
    if os.environ.get("NOTION_TOKEN"):
        config["token"] = os.environ.get("NOTION_TOKEN")
    if os.environ.get("NOTION_PAGE_ID"):
        config["page_id"] = os.environ.get("NOTION_PAGE_ID")
        
    # Check SIEM/.env if not completely set
    if (not config["token"] or not config["page_id"]) and os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r") as f:
            for line in f:
                if line.startswith("NOTION_TOKEN="):
                    config["token"] = line.strip().split("=", 1)[1]
                elif line.startswith("NOTION_PAGE_ID="):
                    config["page_id"] = line.strip().split("=", 1)[1]
                    
    return config

def save_notion_config(token, page_id):
    """Saves Notion configuration to SIEM/.env file for future executions."""
    if not os.path.exists(ENV_PATH):
        print(f"[!] Warning: {ENV_PATH} not found. Creating a new one.")
        
    # Read existing content
    lines = []
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r") as f:
            lines = f.readlines()
            
    # Filter out existing keys
    new_lines = []
    for line in lines:
        if not line.startswith("NOTION_TOKEN=") and not line.startswith("NOTION_PAGE_ID="):
            new_lines.append(line)
            
    # Ensure there is a newline at the end if not empty
    if new_lines and not new_lines[-1].endswith("\n"):
        new_lines[-1] += "\n"
        
    # Append new configurations
    new_lines.append(f"\n# Notion API Integration Keys\n")
    new_lines.append(f"NOTION_TOKEN={token}\n")
    new_lines.append(f"NOTION_PAGE_ID={page_id}\n")
    
    with open(ENV_PATH, "w") as f:
        f.writelines(new_lines)
    print(f"[*] Saved Notion credentials in {ENV_PATH} successfully.")

def get_credentials_from_user():
    """Prompts the user to input Notion Credentials with detailed instructions."""
    print("\n[!] Notion Integration Credentials are required.")
    print("    1. Go to https://www.notion.so/my-integrations and click 'New Integration'")
    print("    2. Copy the 'Internal Integration Token' (ntn_...)")
    print("    3. Open your target Notion Page in a browser")
    print("    4. Click the '...' (top right) -> Connections -> Add Connections -> search & add your Integration")
    print("    5. Copy the 32-character Page ID from the URL (at the end of the URL, e.g., page-title-xxxxxxxxxxxx)")
    print("-" * 60)
    
    token = input("Enter your Notion Integration Token (ntn_...): ").strip()
    page_id = input("Enter your Notion Page ID: ").strip()
    
    if not token or not page_id:
        print("[!] Error: Token and Page ID cannot be empty.")
        sys.exit(1)
        
    # Standardize page_id (remove hyphens or parse from URL if full URL is pasted)
    if "notion.so/" in page_id:
        # Extract the last 32 hex chars
        match = re.search(r"([a-f0-9]{32})", page_id)
        if match:
            page_id = match.group(1)
            
    save_choice = input("Do you want to save these credentials to SIEM/.env for next time? (y/n): ").strip().lower()
    if save_choice == 'y':
        save_notion_config(token, page_id)
        
    return token, page_id

def text_to_rich_text(text):
    """Parses bold markdown (**text**) and inline code (`code`) into Notion Rich Text objects."""
    tokens = []
    pattern = re.compile(r"(\*\*[^*]+\*\*|`[^`]+`)")
    parts = pattern.split(text)
    
    for part in parts:
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            content = part[2:-2]
            tokens.append({
                "type": "text",
                "text": {"content": content},
                "annotations": {"bold": True}
            })
        elif part.startswith("`") and part.endswith("`"):
            content = part[1:-1]
            tokens.append({
                "type": "text",
                "text": {"content": content},
                "annotations": {"code": True}
            })
        else:
            tokens.append({
                "type": "text",
                "text": {"content": part}
            })
            
    if not tokens:
        tokens.append({
            "type": "text",
            "text": {"content": text}
        })
    return tokens

def get_h2_title(filepath):
    """Parses the markdown file to find the first H2 heading (starting with '## ') to use as the page title."""
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                for line in f:
                    match = re.match(r"^##\s+(.*)$", line)
                    if match:
                        title_text = match.group(1).strip()
                        # Clean up any markdown bold or trailing hashes/ticks
                        title_text = re.sub(r"\*\*|`", "", title_text)
                        return title_text
        except Exception as e:
            print(f"[!] Warning: Could not parse H2 title from {filepath}: {e}")
    # Default fallback
    return "🌳 WIDS & ELK SIEM Checklist"

def parse_markdown_checklist(filepath):
    """Parses wids_siem_elk_checklist.md into a structured, hierarchical Python tree list."""
    if not os.path.exists(filepath):
        print(f"[!] Error: Checklist file not found at '{filepath}'")
        sys.exit(1)
        
    print(f"[*] Parsing checklist file: {filepath}...")
    
    tree = []
    last_level0 = None
    last_level1 = None
    
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            # Check if line matches a checkbox list item: - [ ] or - [x] or - [X]
            match = re.match(r"^(\s*)-\s*\[([ xX~])\]\s*(.*)$", line)
            if match:
                spaces = match.group(1)
                status = match.group(2).lower()
                text = match.group(3).strip()
                
                # Determine levels: 0, 2 or 4 spaces
                indent = len(spaces)
                level = 0
                if indent >= 4:
                    level = 2
                elif indent >= 2:
                    level = 1
                
                # ~ is sometimes used for in-progress; we can mark it unchecked in Notion
                checked = status in ['x']
                
                node = {
                    "text": text,
                    "checked": checked,
                    "children": []
                }
                
                if level == 0:
                    tree.append(node)
                    last_level0 = node
                    last_level1 = None
                elif level == 1:
                    if last_level0 is not None:
                        last_level0["children"].append(node)
                        last_level1 = node
                elif level == 2:
                    if last_level1 is not None:
                        last_level1["children"].append(node)
                    elif last_level0 is not None:
                        last_level0["children"].append(node)
                        
    print(f"[*] Successfully parsed {sum(1 + len(x['children']) + sum(len(y['children']) for y in x['children']) for x in tree)} checklist items.")
    return tree

def call_notion_api(endpoint, method, token, data=None):
    """Executes a Notion REST API Call using Python standard library (urllib)."""
    url = f"https://api.notion.com{endpoint}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Notion-Version": "2022-06-28"
    }
    
    req_data = json.dumps(data).encode('utf-8') if data else None
    req = urllib.request.Request(
        url,
        data=req_data,
        headers=headers,
        method=method
    )
    
    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        error_body = e.read().decode('utf-8')
        print(f"\n[!] Notion API HTTP Error ({e.code}): {e.reason}")
        print(f"    Response body: {error_body}")
        raise e
    except Exception as e:
        print(f"\n[!] Error connecting to Notion API: {e}")
        raise e

def node_to_block(node):
    """Converts a tree node and all its children recursively into Notion Block syntax."""
    block = {
        "object": "block",
        "type": "to_do",
        "to_do": {
            "rich_text": text_to_rich_text(node["text"]),
            "checked": node["checked"]
        }
    }
    if node["children"]:
        block["to_do"]["children"] = [node_to_block(c) for c in node["children"]]
    return block

def clear_existing_page_children(page_id, token):
    """Fetches and deletes all existing block children on a page to ensure a clean sync."""
    print("[*] Checking for existing blocks to clean up...")
    try:
        res = call_notion_api(f"/v1/blocks/{page_id}/children?page_size=100", "GET", token)
        results = res.get("results", [])
        if results:
            print(f"[*] Found {len(results)} existing blocks. Cleaning up...")
            for block in results:
                block_id = block["id"]
                call_notion_api(f"/v1/blocks/{block_id}", "DELETE", token)
            print("[*] Cleaned up existing blocks successfully.")
    except Exception as e:
        print(f"[!] Warning: Could not clear page children (it might be a fresh sub-page): {e}")

def main():
    print_banner()
    
    # 1. Load or prompt credentials
    config = load_notion_config()
    token = config["token"]
    page_id = config["page_id"]
    
    if not token or not page_id:
        token, page_id = get_credentials_from_user()
    else:
        print(f"[*] Loaded credentials from SIEM/.env")
        print(f"    Page ID: {page_id[:8]}...{page_id[-8:]}")
        use_saved = input("Do you want to use these saved credentials? (y/n) [y]: ").strip().lower()
        if use_saved == 'n':
            token, page_id = get_credentials_from_user()
            
    # 2. Choose Markdown file to sync
    if len(sys.argv) > 1:
        arg_path = sys.argv[1]
        if os.path.exists(arg_path):
            checklist_path = arg_path
            print(f"[*] File từ dòng lệnh: {checklist_path}")
        else:
            print(f"[!] Warning: '{arg_path}' không tồn tại. Chuyển sang chọn thủ công.")
            checklist_path = choose_md_file()
    else:
        checklist_path = choose_md_file()

    # 3. Ask for Syncing Mode
    print("\nChoose Sync Mode:")
    print("  1. Create a NEW SUB-PAGE inside the target page (Recommended, clean & fast)")
    print("  2. Sync DIRECTLY to the target page (Clears existing contents on that page first)")
    choice = input("Enter choice (1 or 2) [1]: ").strip()
    if not choice:
        choice = "1"
        
    # 4. Parse Markdown
    tree = parse_markdown_checklist(checklist_path)
    h2_title = get_h2_title(checklist_path)
    
    if choice == "1":
        print(f"\n[*] Creating a NEW sub-page with title: '{h2_title}'...")
        # Create page
        page_payload = {
            "parent": {"type": "page_id", "page_id": page_id},
            "properties": {
                "title": {
                    "type": "title",
                    "title": [
                        {
                            "type": "text",
                            "text": {"content": h2_title}
                        }
                    ]
                }
            }
        }
        
        try:
            new_page_res = call_notion_api("/v1/pages", "POST", token, page_payload)
            new_page_id = new_page_res["id"]
            new_page_url = new_page_res["url"]
            print(f"[+] Successfully created new page: {new_page_res.get('properties', {}).get('title', {}).get('title', [{}])[0].get('text', {}).get('content', '')}")
            
            # Sync blocks in chunks (grouping top level blocks one-by-one to avoid payload limits)
            print("[*] Synchronizing checklist blocks to the new page...")
            for index, item in enumerate(tree):
                sys.stdout.write(f"\r[*] Syncing section {index+1}/{len(tree)}: {item['text'][:30]}...")
                sys.stdout.flush()
                
                block_payload = {
                    "children": [node_to_block(item)]
                }
                call_notion_api(f"/v1/blocks/{new_page_id}/children", "PATCH", token, block_payload)
                
            print("\n[+] Synchronization Complete!")
            print("=" * 60)
            print(f"👉 OPEN YOUR SYNCED NOTION CHECKLIST HERE:\n   {new_page_url}")
            print("=" * 60)
            
        except Exception as e:
            print(f"\n[!] Sync failed: {e}")
            sys.exit(1)
            
    else:
        print(f"\n[*] Syncing DIRECTLY to the page {page_id}...")
        
        # Update target page title
        try:
            print(f"[*] Updating target page title to: '{h2_title}'...")
            page_update_payload = {
                "properties": {
                    "title": {
                        "type": "title",
                        "title": [
                            {
                                "type": "text",
                                "text": {"content": h2_title}
                            }
                        ]
                    }
                }
            }
            call_notion_api(f"/v1/pages/{page_id}", "PATCH", token, page_update_payload)
        except Exception as e:
            print(f"[!] Warning: Could not update target page title: {e}")
            
        # Clear existing page contents
        clear_existing_page_children(page_id, token)
        
        # Append header using H2 title
        header_block = {
            "children": [
                {
                    "object": "block",
                    "type": "heading_1",
                    "heading_1": {
                        "rich_text": [
                            {"type": "text", "text": {"content": h2_title}}
                        ]
                    }
                },
                {
                    "object": "block",
                    "type": "paragraph",
                    "paragraph": {
                        "rich_text": [
                            {"type": "text", "text": {"content": f"Tài liệu theo dõi tiến độ tích hợp trực tiếp từ file {os.path.basename(checklist_path)}. Cập nhật mới nhất bằng script sync."}}
                        ]
                    }
                },
                {
                    "object": "block",
                    "type": "divider",
                    "divider": {}
                }
            ]
        }
        
        try:
            print("[*] Creating header layout...")
            call_notion_api(f"/v1/blocks/{page_id}/children", "PATCH", token, header_block)
            
            # Sync blocks
            print("[*] Synchronizing checklist blocks...")
            for index, item in enumerate(tree):
                sys.stdout.write(f"\r[*] Syncing section {index+1}/{len(tree)}: {item['text'][:30]}...")
                sys.stdout.flush()
                
                block_payload = {
                    "children": [node_to_block(item)]
                }
                call_notion_api(f"/v1/blocks/{page_id}/children", "PATCH", token, block_payload)
                
            print("\n[+] Direct Synchronization Complete!")
            print("=" * 60)
            print(f"👉 Refresh your Notion page to view the updated checklist!")
            print("=" * 60)
            
        except Exception as e:
            print(f"\n[!] Sync failed: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
