import re

def detailed_regex_analysis(file_path):
    print(f"Deep diving {file_path}...")
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    # 1. Search for any JSON response content that mentions "ip", "port", "addr", "host"
    # The simple regex failed, maybe because they are not key-value pairs like "ip": "..." or maybe the response is encoded/compressed.
    # HAR files store response content in "text" field, sometimes base64 encoded.

    # Check for "base64" encoding
    base64_indicators = re.findall(r'"encoding"\s*:\s*"base64"', content)
    if base64_indicators:
        print(f"Found {len(base64_indicators)} base64 encoded responses. You might need to decode them.")

    # Let's search for "text": "..." content and see if we can spot anything interesting inside
    # We will limit the output size
    text_contents = re.findall(r'"text"\s*:\s*"(.*?)"', content)
    print(f"Found {len(text_contents)} response bodies.")

    interesting_keywords = ["ip", "port", "address", "server", "battle", "udp", "tcp", "game"]

    found_interesting = []

    for text in text_contents:
        # Simple check if it looks like JSON inside the string
        # Unescape the string first (basic unescape)
        unescaped_text = text.replace('\\"', '"').replace('\\\\', '\\')

        for keyword in interesting_keywords:
            if keyword in unescaped_text.lower():
                # Extract a snippet around the keyword
                idx = unescaped_text.lower().find(keyword)
                start = max(0, idx - 50)
                end = min(len(unescaped_text), idx + 100)
                snippet = unescaped_text[start:end]
                found_interesting.append(f"Keyword '{keyword}': ...{snippet}...")

    print(f"Found {len(found_interesting)} interesting snippets.")
    for snippet in found_interesting[:20]:
        print(snippet)

if __name__ == "__main__":
    detailed_regex_analysis('login-dari-awal-bagian-1.har')
    print("-" * 30)
    detailed_regex_analysis('login-dari-awal-bagian-2.har')
