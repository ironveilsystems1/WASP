#!/usr/bin/env python3
"""Every wasp-menu option must have a help card.

The menu's guidance layer only helps a first-time operator if it is
COMPLETE. An option with no card falls through to "No help for that",
which is worse than no help system at all: the operator learns the
feature is unreliable and stops trying it.

This is the same failure shape the rest of this suite guards against --
something that looks present and silently is not. So it is asserted
rather than left to review: add a menu option, add its card, or this
fails.
"""
import re, sys

MENU = 'payload/bin/wasp-menu.sh'
# submenu function -> help key prefix, as wired in the _sel calls
PREFIX = {
    'menu_health': 'health', 'menu_backup': 'backup', 'menu_security': 'security',
    'menu_updates': 'updates', 'menu_import': 'import', 'menu_diagnostics': 'diag',
    'menu_testing': 'testing',
}

src = open(MENU).read()

# Options as DISPLAYED to the operator: numbered lines inside the heredocs
# that render each menu. The dispatch `case` arms use the same numbers but
# also carry shell, so the display lines are the honest source.
options = set()
cur = None
for line in src.split('\n'):
    m = re.match(r'^([a-z_]+)\(\) \{', line)
    if m:
        cur = PREFIX.get(m.group(1))
    # Match both the DISPLAY lines (which may lead with ${RED}[!]${R}) and
    # the dispatch arms (which may lead with _have, run, if, a colour, or a
    # nested menu call). Being narrow here silently under-counts options,
    # which would let a missing card pass as "clean" -- the exact failure
    # this check exists to prevent.
    if cur and re.match(r'^\s+(\$\{[A-Z]+\})?\d+\)\s+\S', line):
        n = re.search(r'(\d+)\)', line).group(1)
        options.add(f'{cur}.{n}')

cards = set(re.findall(r'^  ([a-z]+\.(?:menu|\d+))\) _card', src, re.M))

missing = sorted(options - cards)
orphan  = sorted(c for c in cards - options if not c.endswith('.menu') and not c.startswith('main.'))

if missing:
    print(f'FOUND {len(missing)} menu option(s) with no help card:')
    for m in missing:
        print(f'  {m}')
    print('\n  Each falls through to "No help for that", which teaches the')
    print('  operator the help system is unreliable. Add a _card for each.')
    sys.exit(1)

# Every submenu needs an overview card too.
no_overview = sorted(p for p in set(PREFIX.values()) if f'{p}.menu' not in cards)
if no_overview:
    print(f'Submenu(s) with no overview card (? on its own): {", ".join(no_overview)}')
    sys.exit(1)

if orphan:
    print(f'NOTE: {len(orphan)} card(s) for options that no longer exist:')
    for o in orphan:
        print(f'  {o}')
    print('  Harmless, but they are dead text — remove or re-point them.')

print(f'Menu-help coverage: CLEAN — {len(options)} options, '
      f'{len(set(PREFIX.values()))} overviews, all have cards')
