.PHONY: help check unit detect coverage semantic fuzz falsepos drift-freeze \
	drift anomalies selftest fixtures expected sync

help:
	@echo "make check      run everything (detection + self-scan + sync check)"
	@echo "make unit       table-driven tests for the pure functions"
	@echo "make detect     detection benchmark against fixtures/"
	@echo "make coverage   exact per-fixture findings + per-family recall/precision"
	@echo "make semantic   semantic cross-check tests (synthetic panel)"
	@echo "make fuzz       malformed and hostile inputs: must not crash or hang"
	@echo "make falsepos   false-positive benchmark against installed extensions"
	@echo "make drift      diff that corpus against the frozen report: any finding"
	@echo "                gained OR lost fails, and a crash is its own failure"
	@echo "make drift-freeze     re-record the frozen report (review the diff)"
	@echo "make anomalies  invariant sweep: is the OUTPUT well-formed"
	@echo "make selftest   scan this repo with its own scanner"
	@echo "make fixtures   regenerate fixtures/ from tests/make_fixtures.py"
	@echo "make expected   re-record fixtures/EXPECTED.json (review the diff)"
	@echo "make sync       copy scanner/ into the installable skill bundle"

check: unit detect coverage semantic fuzz selftest version
	@diff -rq --exclude='__pycache__' scanner skills/inspect-skill/scanner >/dev/null \
		&& echo "bundle in sync" \
		|| (echo "BUNDLE OUT OF SYNC — run: make sync"; exit 1)

# Two hand-written strings that have to agree: the version the code carries and
# the version the installable bundle advertises. They disagreed silently for the
# whole life of the repo — 0.1.0 against 0.2 — because nothing ever compared
# them and neither one was printed anywhere a reader could see it.
version:
	@python3 -c "\
import re,sys; sys.path.insert(0,'.');\
from scanner import __version__ as v;\
m=re.search(r'^  version: \"([^\"]+)\"', open('skills/inspect-skill/SKILL.md').read(), re.M);\
s=m.group(1) if m else 'MISSING';\
print(f'version {v}') if s==v else sys.exit(f'VERSION MISMATCH: scanner {v}, SKILL.md {s}')"

# Runs first, and deliberately so. Every case here pins an invariant a docstring
# already promised; when a demotion heuristic changes, this is what tells you
# which promise you just broke. The whole queue of evasions this suite was
# written for existed because nothing enforced those promises.
unit:
	@python3 -m tests.unit_test

detect:
	@python3 -m tests.truepos

# `detect` proves the attack is caught at the points somebody thought to pin.
# This proves the rest: every fixture's EXACT id set, so a rule that quietly
# stops firing fails here even when no `must_detect` names it — and per-family
# coverage, so a family measured by nothing looks different from a family that
# passes. Four defects in a row read as coverage and were not.
coverage:
	@python3 -m tests.coverage

# verify() is pure Python, so the panel is synthetic: no model, repeatable.
semantic:
	@python3 -m tests.semantic_test

# A crash on a malformed bundle is a denial of audit, and a hang is the
# same thing with extra steps. Both are failures here.
fuzz:
	@python3 -m tests.fuzz

# Needs a corpus of extensions you already trust. Defaults to Claude Code's.
falsepos:
	@python3 -m bench.corpus $${CORPUS:-$$HOME/.claude}

# ONE target, one scan, one frozen file — because precision and recall are two
# readings of the same measurement, and splitting them into `precision` and
# `recall` would rescan 76 units twice and let two baselines disagree about
# which corpus they describe. It is not called `precision` any more for the
# reason this half was built: that name promised half of what the file checks,
# and a rule that STOPPED firing on real software passed it clean.
#
# Deliberately NOT part of `check`. It reads a machine-specific directory that
# CI does not have, and a check that reports success when it measured nothing is
# the failure mode the whole benchmark exists to catch. So it stands alone and
# exits 2 — "did not run" — when the corpus is absent, empty, or a different
# size than the one the report was frozen on. 0 pass, 1 regression, 2
# unmeasured: three outcomes, never two.
drift:
	@python3 -m bench.drift $${CORPUS:-$$HOME/.claude}

drift-freeze:
	@python3 -m bench.drift --freeze $${CORPUS:-$$HOME/.claude}

# Asks a different question than falsepos: not "is the verdict noisy" but
# "is the output well-formed". Every hand-found bug so far was this shape.
anomalies:
	@python3 -m bench.anomalies $${CORPUS:-$$HOME/.claude}

# The scanner must stay quiet on its own source: a rules catalogue is full of
# attack patterns, and flagging them is the failure mode this project exists
# to avoid. Non-zero headline findings here are a regression in position.py.
selftest:
	@python3 -m scanner . --json | python3 -c "\
import json,sys; sys.path.insert(0,'.');\
from scanner.engine import headline;\
d=json.load(sys.stdin);\
n=len([f for f in d['findings'] if f['disclosure'] in ('undeclared','euphemistic')\
 and f['severity'] in ('CRITICAL','HIGH') and f['confidence'] in ('high','medium')]);\
print(f'self-scan headline: {n}')"

fixtures:
	@python3 -m tests.make_fixtures

# Separate from `fixtures` on purpose. `make_fixtures` writes INTENT — the
# hand-written must_detect beside each sample. This records OBSERVATION: what
# the scanner actually produces today. Regenerating must be a deliberate act
# whose diff a human reads, not a side effect of touching the corpus.
expected:
	@python3 -m tests.coverage --update

# --delete matters. `cp` only ever adds, so a module deleted from scanner/ kept
# shipping inside the installable skill — the bundle would still import a file
# the source tree had removed, and `make check`'s diff was the only thing that
# ever noticed.
sync:
	@rsync -a --delete --exclude='__pycache__' scanner/ skills/inspect-skill/scanner/ \
		&& echo "bundle synced"
