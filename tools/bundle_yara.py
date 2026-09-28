#!/usr/bin/env python3
"""Build a reproducible Linux-only release bundle from the local YARA Forge Core file."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
# Tokenize strings, regexes and comments before braces: a brace in a pattern
# must never truncate a rule or turn its contents into a second rule.
TOKEN = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|/(?:\\.|[^/\\\n])+/[is]*|[A-Za-z_]\w*|\S', re.S)
RULE_START = re.compile(r'(?:(?:private|global)\s+)*rule\s+(\w+)\b')
META = re.compile(r'^\s*(\w+)\s*=\s*"((?:\\.|[^"\\])*)"', re.M)
LINUX = re.compile(r'(?:^|[^a-z])(linux|elf|unix|posix)(?:$|[^a-z])', re.I)
OTHER = re.compile(r'(?:^|[^a-z])(windows|win32|win64|winnt|powershell|macos|osx|macho|android|ios)(?:$|[^a-z])', re.I)


def parse_rules(source):
    tokens = list(TOKEN.finditer(source))
    result = []
    index = 0
    prefix_end = 0
    while index < len(tokens):
        token = tokens[index]
        if token.group() not in ('rule', 'private', 'global'):
            index += 1
            continue
        header = RULE_START.match(source, token.start())
        if not header:
            index += 1
            continue
        start = token.start()
        while index < len(tokens) and tokens[index].group() != '{':
            index += 1
        depth = 0
        while index < len(tokens):
            value = tokens[index].group()
            depth += (value == '{') - (value == '}')
            index += 1
            if depth == 0:
                break
        if depth or index == len(tokens) and tokens[index - 1].group() != '}':
            raise ValueError('unterminated rule: ' + header.group(1))
        end = tokens[index - 1].end()
        text = source[start:end]
        meta_start = text.find('meta:')
        meta_end = text.find('strings:')
        if meta_end < 0:
            meta_end = text.find('condition:')
        metadata = dict(META.findall(text[meta_start:meta_end])) if meta_start >= 0 else {}
        condition = text[text.rfind('condition:') + len('condition:'):]
        # Keep repository license comments alongside their original rules.
        comments = '\n'.join(t.group() for t in TOKEN.finditer(source[prefix_end:start]) if t.group().startswith(('/*', '//')))
        result.append({'name': header.group(1), 'content': text, 'metadata': metadata,
                       'condition': condition, 'comments': comments,
                       'private': 'private' in source[start:header.end()].split()})
        prefix_end = end
    if not result:
        raise ValueError('source contains no YARA rules')
    return result


def classification(rule):
    meta = rule['metadata']
    labels = ' '.join([rule['name']] + [meta.get(k, '') for k in ('description', 'tags', 'platform', 'os', 'malware_type')])
    condition = rule['condition']
    # Reject PE/.NET and explicitly foreign targets even if they mention Linux.
    if OTHER.search(labels) or re.search(r'\b(?:pe|dotnet)\s*\.|0x(?:5a4d|4d5a)\b', condition, re.I):
        return 'foreign'
    if LINUX.search(labels) or re.search(r'\belf\s*\.|0x(?:464c457f|7f454c46)\b', condition, re.I):
        return 'linux'
    return 'unclassified'


def build(source, platform='linux'):
    if platform != 'linux':
        raise ValueError('only linux release bundles are supported')
    rules = parse_rules(source)
    by_name = {r['name']: r for r in rules}
    if len(by_name) != len(rules):
        raise ValueError('duplicate rule identifiers')
    chosen = {r['name'] for r in rules if classification(r) == 'linux'}
    # Include only compatible dependencies; never leave dangling rule references.
    def dependencies(name, visiting):
        if name in visiting:
            return set()
        visiting = visiting | {name}
        rule = by_name[name]
        if classification(rule) == 'foreign':
            raise ValueError(name)
        needed = {name}
        for token in TOKEN.finditer(rule['condition']):
            dep = token.group()
            if dep in by_name:
                needed |= dependencies(dep, visiting)
        return needed
    selected = set()
    for name in chosen:
        try:
            selected |= dependencies(name, set())
        except ValueError:
            continue
    # Unclassified global rules could alter every selected rule's meaning.
    for rule in rules:
        if re.match(r'(?:private\s+)?global\s', rule['content']) and classification(rule) == 'unclassified':
            selected |= dependencies(rule['name'], set())
    filtered = [r for r in rules if r['name'] in selected]
    if not filtered:
        raise ValueError('no Linux rules selected')
    imports = re.findall(r'^\s*import\s+"([^"]+)"', source, re.M)
    used_imports = [module for module in imports if any(re.search(r'\b' + re.escape(module) + r'\s*\.', r['condition']) for r in filtered)]
    # Preserve all upstream copyright/license repository headers, including those
    # preceding an excluded rule in the same repository section.
    notices = '\n\n'.join(r['comments'] for r in rules if r['comments'])
    content = '// Generated by tools/bundle_yara.py; replace the source on each release.\n' + notices + '\n'
    content += '\n'.join('import "' + module + '"' for module in used_imports) + '\n\n'
    content += '\n\n'.join(r['content'] for r in filtered) + '\n'
    version = re.search(r'Creation Date:\s*([^\r\n]+)', source)
    catalog = {'source': 'YARA Forge Core', 'version': version.group(1).strip() if version else 'local',
               'platform': platform, 'rules_sha256': hashlib.sha256(content.encode()).hexdigest(),
               'source_sha256': hashlib.sha256(source.encode()).hexdigest(), 'rule_count': len(filtered), 'rules': []}
    for rule in filtered:
        meta = rule['metadata']
        catalog['rules'].append({'name': rule['name'], 'tags': [s.strip() for s in meta.get('tags', '').split(',') if s.strip()],
                                 'description': meta.get('description', ''), 'author': meta.get('author', ''),
                                 'reference': meta.get('reference', ''), 'content': rule['content']})
    return content, catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT / 'yara-forge-core/yara-rules-core.yar')
    parser.add_argument('--output', type=Path, default=ROOT / 'internal/detection/malware/bundle')
    parser.add_argument('--platform', default='linux')
    args = parser.parse_args()
    source = args.source.read_text()
    content, catalog = build(source, args.platform)
    args.output.mkdir(parents=True, exist_ok=True)
    (args.output / 'linux.yar').write_text(content)
    (args.output / 'catalog.json').write_text(json.dumps(catalog, indent=2) + '\n')
    print(f"Bundled {catalog['rule_count']} Linux rules ({catalog['rules_sha256']})")


if __name__ == '__main__':
    main()
