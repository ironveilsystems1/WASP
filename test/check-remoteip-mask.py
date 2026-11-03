#!/usr/bin/env python3
"""
check-remoteip-mask.py — does the remoteip.conf mask survive a container rebuild?

WHY THIS EXISTS

The WordPress image ships conf-enabled/remoteip.conf declaring every RFC1918
range an internal proxy. Removing it inside the container lasted until the
GeoIP rebuild later in the same stage (defect 32). 10.5 replaced the removal
with a read-only bind mount and said in a comment that the mount was "re-applied
by every podman run in this script by construction".

It was not. The mount went into WP_VOL_ARGS, which only the first `podman run`
reads. The three other paths that recreate the container -- wp-geoip-setup.sh,
the OpenRC service, update.sh -- share only what is in wp-run-extra.env, and the
mask was added after that file was written. Stage 06 verified the mask once,
before the rebuild, printed its success line, and moved on. The fix for a control
that reverted itself reverted itself the same way.

So this checks the shape that matters rather than the presence of the mount:

  MASK-ENV     the mount joins WP_EXTRA_VOLS before wp-run-extra.env is written
  MASK-READ    every path that recreates the container reads that file and
               passes $WP_EXTRA_VOLS to `podman run`
  MASK-REVERIFY  stage 06 re-checks after the GeoIP rebuild
  MASK-LIVE    validate-wordpress.sh asks the running container, and cannot
               read a failed exec as a pass

Static: this proves the code says the right thing, and nothing about a live VM.
validate-wordpress.sh is the check that runs against the box.
"""

import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MASK = "/etc/apache2/conf-enabled/remoteip.conf:ro"
STAGE06 = "payload/stages/06-containers-mariadb-wordpress.sh"
STAGE07 = "payload/stages/07-openrc-services.sh"
GEOIP = "payload/bin/wp-geoip-setup.sh"
UPDATE = "payload/bin/update.sh"
VALIDATE = "payload/bin/validate-wordpress.sh"


def read(rel, root=REPO):
    with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as f:
        return f.read()


def code_lines(text):
    """Lines with comments dropped, keeping numbering by index."""
    return [re.sub(r"^\s*#.*$", "", l) for l in text.splitlines()]


def check_stage06(text):
    problems = []
    lines = code_lines(text)
    env_write = next((i for i, l in enumerate(lines)
                      if "> /etc/wp-install/wp-run-extra.env" in l), None)
    mask_extra = next((i for i, l in enumerate(lines)
                       if l.lstrip().startswith("WP_EXTRA_VOLS=") and MASK in l), None)
    if env_write is None:
        problems.append("MASK-ENV: stage 06 no longer writes wp-run-extra.env")
    if mask_extra is None:
        problems.append("MASK-ENV: the mask is not added to WP_EXTRA_VOLS, so only "
                        "the first podman run gets it")
    elif env_write is not None and mask_extra > env_write:
        problems.append("MASK-ENV: the mask joins WP_EXTRA_VOLS after "
                        "wp-run-extra.env is written, so the file does not carry it")

    calls = [i for i, l in enumerate(lines)
             if re.match(r"\s*(\[.*\]\s*&&\s*)?_verify_remoteip_mask\b", l)]
    geoip = next((i for i, l in enumerate(lines)
                  if "/usr/local/bin/wp-geoip-setup.sh; then" in l), None)
    if geoip is None:
        problems.append("MASK-REVERIFY: could not find the GeoIP rebuild in stage 06")
    elif not any(c > geoip for c in calls):
        problems.append("MASK-REVERIFY: nothing re-checks the mask after the GeoIP "
                        "rebuild, so the install reports on a replaced container")
    return problems


def check_consumer(name, text):
    """A path that recreates the container must carry the shared list."""
    problems = []
    if "/etc/wp-install/wp-run-extra.env" not in text:
        problems.append(f"MASK-READ: {name} does not read wp-run-extra.env")
    if not re.search(r"\\?\$\{?WP_EXTRA_VOLS\}?", "\n".join(
            l for l in code_lines(text) if "WP_EXTRA_VOLS=" not in l)):
        problems.append(f"MASK-READ: {name} never passes WP_EXTRA_VOLS to podman run")
    return problems


def check_validator(text):
    problems = []
    if "conf-enabled/remoteip.conf" not in text:
        problems.append("MASK-LIVE: validate-wordpress.sh does not ask the running "
                        "container about the mask")
    elif re.search(r"if\s+podman exec wordpress test -s /etc/apache2/conf-enabled/remoteip",
                   text):
        problems.append("MASK-LIVE: an exit-code test reads a failed exec as 'masked'")
    return problems


def scan(root=REPO):
    problems = check_stage06(read(STAGE06, root))
    for rel in (STAGE07, GEOIP, UPDATE):
        problems += check_consumer(rel, read(rel, root))
    problems += check_validator(read(VALIDATE, root))
    return problems


def self_test():
    # The defect as it shipped in 10.5.
    bad = "\n".join([
        'WP_EXTRA_VOLS="-v /a:/b:ro"',
        'printf x > /etc/wp-install/wp-run-extra.env',
        'WP_VOL_ARGS="${WP_VOL_ARGS} -v /m:' + MASK + '"',
        'podman exec wordpress test -s /etc/apache2/conf-enabled/remoteip.conf',
        'if /usr/local/bin/wp-geoip-setup.sh; then',
        'fi',
    ])
    got = check_stage06(bad)
    assert any("MASK-ENV" in p for p in got), "self-test: WP_VOL_ARGS mount not caught"
    assert any("MASK-REVERIFY" in p for p in got), "self-test: missing re-check not caught"

    # Added to the right list, too late.
    late = "\n".join([
        'printf x > /etc/wp-install/wp-run-extra.env',
        'WP_EXTRA_VOLS="${WP_EXTRA_VOLS} -v /m:' + MASK + '"',
    ])
    assert any("after" in p for p in check_stage06(late)), "self-test: late mount not caught"

    # Correct shape.
    good = "\n".join([
        'WP_EXTRA_VOLS="${WP_EXTRA_VOLS} -v /m:' + MASK + '"',
        'printf x > /etc/wp-install/wp-run-extra.env',
        '_verify_remoteip_mask',
        'if /usr/local/bin/wp-geoip-setup.sh; then',
        'fi',
        '[ "$G" = "1" ] && _verify_remoteip_mask "after"',
    ])
    assert not check_stage06(good), f"self-test: clean fixture flagged: {check_stage06(good)}"

    assert check_consumer("x", "podman run image"), "self-test: bare consumer not caught"
    assert not check_consumer("x", ". /etc/wp-install/wp-run-extra.env\npodman run ${WP_EXTRA_VOLS} i")
    assert not check_consumer("x", ". /etc/wp-install/wp-run-extra.env\n  \\$WP_EXTRA_VOLS \\\\")
    assert check_validator("if podman exec wordpress test -s /etc/apache2/conf-enabled/remoteip.conf; then")
    assert check_validator("nothing here")
    assert not check_validator('sh -c "if [ -s /etc/apache2/conf-enabled/remoteip.conf ]"')
    return True


def main():
    self_test()
    problems = scan()
    if problems:
        print(f"remoteip mask: {len(problems)} problem(s)")
        for p in problems:
            print(f"  {p}")
        return 1
    print("remoteip mask: CLEAN — carried by wp-run-extra.env to every rebuild path, "
          "re-verified after GeoIP, asserted live")
    return 0


if __name__ == "__main__":
    sys.exit(main())
