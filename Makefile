.PHONY: help check unit detect semantic fuzz falsepos anomalies selftest fixtures sync

help:
	@echo "make check      run everything (detection + self-scan + sync check)"
	@echo "make unit       table-driven tests for the pure functions"
	@echo "make detect     detection benchmark against fixtures/"
	@echo "make semantic   semantic cross-check tests (synthetic panel)"
	@echo "make fuzz       malformed and hostile inputs: must not crash or hang"
	@echo "make falsepos   false-positive benchmark against installed extensions"
	@echo "make anomalies  invariant sweep: is the OUTPUT well-formed"
	@echo "make selftest   scan this repo with its own scanner"
	@echo "make fixtures   regenerate fixtures/ from tests/make_fixtures.py"
	@echo "make sync       copy scanner/ into the installable skill bundle"

check: unit detect semantic fuzz selftest
	@diff -rq --exclude='__pycache__' scanner skills/inspect-skill/scanner >/dev/null \
		&& echo "bundle in sync" \
		|| (echo "BUNDLE OUT OF SYNC — run: make sync"; exit 1)

# Runs first, and deliberately so. Every case here pins an invariant a docstring
# already promised; when a demotion heuristic changes, this is what tells you
# which promise you just broke. The whole queue of evasions this suite was
# written for existed because nothing enforced those promises.
unit:
	@python3 -m tests.unit_test

detect:
	@python3 -m tests.truepos

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

# --delete matters. `cp` only ever adds, so a module deleted from scanner/ kept
# shipping inside the installable skill — the bundle would still import a file
# the source tree had removed, and `make check`'s diff was the only thing that
# ever noticed.
sync:
	@rsync -a --delete --exclude='__pycache__' scanner/ skills/inspect-skill/scanner/ \
		&& echo "bundle synced"
