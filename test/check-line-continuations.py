import glob, re, sys
# Refined: a COMMENT after a line-continuation is essentially always a bug --
# it swallows the rest of the logical line, silently truncating the command's
# arguments, and `sh -n` passes. A STATEMENT after a continuation is only
# suspicious when the continuation is NOT a legitimate operator continuation
# (`&& \`, `|| \`, `| \`), which is idiomatic and correct.
OP_END = re.compile(r'(&&|\|\||\||;)\s*\\$')
# The command names are matched with a following space or end-of-line, not a
# bare \b. `\b` treats a dot as a word boundary, so `install\b` also matched
# the FILENAME `install.sh` — which in this repo is the single most-referenced
# path, and appears legitimately as the argument of a continued command:
#
#     sed "s|...|...|" \
#       install.sh > "$tmp"
#
# That is correct shell and was reported as a split command. A check that
# misfires on the most common filename in the tree is one people start
# ignoring, so the pattern now requires the name to be the command.
STATEMENT = re.compile(r'^\s*(\}|\{|(mkdir|chmod|chown|install|cat|rm|cp)(\s|$))')
problems = []
for f in sorted(set(glob.glob('**/*.sh', recursive=True)) | {'install.sh'}):
    try: lines = open(f, errors='replace').read().split('\n')
    except FileNotFoundError: continue
    for i in range(len(lines)-1):
        cur, nxt = lines[i], lines[i+1]
        c = cur.rstrip()
        # A line that is ITSELF a comment cannot open a continuation: the
        # trailing backslash is just comment text. This shows up in help
        # output that wraps a long example command across two commented
        # lines, and treating it as a continuation is a false positive.
        if cur.lstrip().startswith('#'): continue
        if not c.endswith('\\') or c.endswith('\\\\'): continue
        st = nxt.lstrip()
        if st.startswith('#'):
            problems.append((f, i+2, 'ERROR', 'comment after line-continuation truncates the command', nxt.strip()[:55]))
        elif STATEMENT.match(nxt) and not OP_END.search(c):
            problems.append((f, i+2, 'ERROR', 'statement after line-continuation splits the command', nxt.strip()[:55]))
if problems:
    print(f"FOUND {len(problems)} problem(s):")
    for f, ln, sev, why, txt in problems: print(f"  [{sev}] {f}:{ln}  {why}\n         {txt}")
    sys.exit(1)
print("Line-continuation check: CLEAN")
