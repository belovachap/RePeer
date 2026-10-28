# Copyright (c) 2012-2025 The Peercoin developers
# Copyright (c) 2013-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Pattern rule to print variables, e.g. make print-top_srcdir
print-%:
	@echo $* = $($*)

ACLOCAL_AMFLAGS = -I build-aux/m4
SUBDIRS = src
.PHONY: deploy FORCE
.INTERMEDIATE: $(COVERAGE_INFO)

export PYTHONPATH

dist_noinst_SCRIPTS = autogen.sh

EXTRA_DIST = $(DIST_SHARE) $(DIST_CONTRIB) $(WINDOWS_PACKAGING) $(BIN_CHECKS)

EXTRA_DIST += \
    test/functional \
    test/fuzz

EXTRA_DIST += \
    test/util/test_runner.py \
    test/util/data/bitcoin-util-test.json \
    test/util/data/blanktxv1.hex \
    test/util/data/blanktxv1.json \
    test/util/data/blanktxv2.hex \
    test/util/data/blanktxv2.json \
    test/util/data/tt-delin1-out.hex \
    test/util/data/tt-delin1-out.json \
    test/util/data/tt-delout1-out.hex \
    test/util/data/tt-delout1-out.json \
    test/util/data/tt-locktime317000-out.hex \
    test/util/data/tt-locktime317000-out.json \
    test/util/data/tx394b54bb.hex \
    test/util/data/txcreate1.hex \
    test/util/data/txcreate1.json \
    test/util/data/txcreate2.hex \
    test/util/data/txcreate2.json \
    test/util/data/txcreatedata1.hex \
    test/util/data/txcreatedata1.json \
    test/util/data/txcreatedata2.hex \
    test/util/data/txcreatedata2.json \
    test/util/data/txcreatedata_seq0.hex \
    test/util/data/txcreatedata_seq0.json \
    test/util/data/txcreatedata_seq1.hex \
    test/util/data/txcreatedata_seq1.json \
    test/util/data/txcreatemultisig1.hex \
    test/util/data/txcreatemultisig1.json \
    test/util/data/txcreatemultisig2.hex \
    test/util/data/txcreatemultisig2.json \
    test/util/data/txcreatemultisig3.hex \
    test/util/data/txcreatemultisig3.json \
    test/util/data/txcreatemultisig4.hex \
    test/util/data/txcreatemultisig4.json \
    test/util/data/txcreatemultisig5.json \
    test/util/data/txcreateoutpubkey1.hex \
    test/util/data/txcreateoutpubkey1.json \
    test/util/data/txcreateoutpubkey2.hex \
    test/util/data/txcreateoutpubkey2.json \
    test/util/data/txcreateoutpubkey3.hex \
    test/util/data/txcreateoutpubkey3.json \
    test/util/data/txcreatescript1.hex \
    test/util/data/txcreatescript1.json \
    test/util/data/txcreatescript2.hex \
    test/util/data/txcreatescript2.json \
    test/util/data/txcreatescript3.hex \
    test/util/data/txcreatescript3.json \
    test/util/data/txcreatescript4.hex \
    test/util/data/txcreatescript4.json \
    test/util/data/txcreatescript5.hex \
    test/util/data/txcreatescript6.hex \
    test/util/data/txcreatesignv1.hex \
    test/util/data/txcreatesignv1.json \
    test/util/data/txcreatesignv2.hex \
    test/util/rpcauth-test.py

clean-local:
	rm -rf coverage_percent.txt test_bitcoin.coverage/ total.coverage/ fuzz.coverage/ test/tmp/ cache/
	rm -rf test/functional/__pycache__ test/functional/test_framework/__pycache__ test/cache share/rpcauth/__pycache__
	rm -rf dist/

test-security-check:
	$(AM_V_at) CC='$(CC)' CFLAGS='$(CFLAGS)' CPPFLAGS='$(CPPFLAGS)' LDFLAGS='$(LDFLAGS)' $(PYTHON) $(top_srcdir)/contrib/devtools/test-security-check.py TestSecurityChecks.test_ELF
	$(AM_V_at) CC='$(CC)' CFLAGS='$(CFLAGS)' CPPFLAGS='$(CPPFLAGS)' LDFLAGS='$(LDFLAGS)' $(PYTHON) $(top_srcdir)/contrib/devtools/test-symbol-check.py TestSymbolChecks.test_ELF

