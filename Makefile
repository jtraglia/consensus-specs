all: help

# A list of executable specifications.
# These must pass a strict linter.
ALL_EXECUTABLE_SPEC_NAMES = \
	phase0    \
	altair    \
	bellatrix \
	capella   \
	deneb     \
	electra   \
	whisk     \
	eip6800   \
	eip7732

# A list of fake targets.
.PHONY: \
	check_toc  \ 
	clean      \
	codespell  \
	gen_all    \
	gen_errors \
	gen_list   \
	help       \
	lint       \
	pyspec     \
	serve_docs

###############################################################################
# Help
###############################################################################

BOLD = $(shell tput bold)
NORM = $(shell tput sgr0)

# Print target descriptions.
help:
	@echo "make $(BOLD)check_toc$(NORM)  -- check table of contents"
	@echo "make $(BOLD)clean$(NORM)      -- delete all untracked files"
	@echo "make $(BOLD)codespell$(NORM)  -- fix all the typos"
	@echo "make $(BOLD)coverage$(NORM)   -- run tests with coverage tracking"
	@echo "make $(BOLD)gen_<gen>$(NORM)  -- run a single generator"
	@echo "make $(BOLD)gen_all$(NORM)    -- run all generators"
	@echo "make $(BOLD)gen_errors$(NORM) -- detect generator errors"
	@echo "make $(BOLD)gen_list$(NORM)   -- list all generator targets"
	@echo "make $(BOLD)lint$(NORM)       -- make the code pretty"
	@echo "make $(BOLD)pyspec$(NORM)     -- generate python specifications"
	@echo "make $(BOLD)serve_docs$(NORM) -- start a local docs web server"

###############################################################################
# Virtual Environment
###############################################################################

VENV_DIR = $(CURDIR)/venv
PYTHON_VENV = $(VENV_DIR)/bin/python3
PIP_VENV = $(VENV_DIR)/bin/pip
VENV = $(VENV_DIR)/.venv_done

# Make a virtual environment will all of the necessary dependencies.
$(VENV): requirements_preinstallation.txt
	@echo "Creating virtual environment"
	@python3 -m venv $(VENV_DIR)
	@$(PIP_VENV) install -r requirements_preinstallation.txt
	@touch $(VENV)

###############################################################################
# Distribution
###############################################################################

# The pyspec is rebuilt to enforce the /specs being part of eth2specs source
# distribution. It could be forgotten otherwise.
dist_build: $(VENV) pyspec
	@$(PYTHON_VENV) setup.py sdist bdist_wheel

# Check the distribution for issues.
dist_check: $(VENV)
	@$(PYTHON_VENV) -m twine check dist/*

# Upload the distribution to PyPI.
dist_upload: $(VENV)
	@$(PYTHON_VENV) -m twine upload dist/*

###############################################################################
# Specification
###############################################################################

TEST_LIBS_DIR = $(CURDIR)/tests/core
PY_SPEC_DIR = $(TEST_LIBS_DIR)/pyspec

# Create the pyspec for all phases.
pyspec: $(VENV)
	@echo "Building all pyspecs"
	@$(PYTHON_VENV) setup.py pyspecdev
	@$(PIP_VENV) install .[docs,lint,test,generator]

###############################################################################
# Testing
###############################################################################

TEST_PRESET_TYPE ?= minimal
TEST_REPORT_DIR = $(PY_SPEC_DIR)/test-reports

# Run pyspec tests.
# To only run tests for a specific fork, do:
#   fork=<fork> make test
# For example:
#   fork=altair make test
test: PYTEST_FORK_OPTION := $(if $(fork),--fork=$(fork))
test: pyspec
	@mkdir -p $(TEST_REPORT_DIR)
	@$(PYTHON_VENV) -m pytest \
		-n auto \
		--bls-type=fastest \
		--preset=$(TEST_PRESET_TYPE) \
		--junitxml=$(TEST_REPORT_DIR)/test_results.xml \
		$(PYTEST_FORK_OPTION) \
		$(PY_SPEC_DIR)/eth2spec

###############################################################################
# Coverage
###############################################################################

COV_HTML_OUT=$(PY_SPEC_DIR)/.htmlcov
COV_INDEX_FILE=$(COV_HTML_OUT)/index.html
COVERAGE_SCOPE := $(foreach S,$(ALL_EXECUTABLE_SPEC_NAMES), --cov=eth2spec.$S.$(TEST_PRESET_TYPE))

# Run pytest with coverage tracking
_test_with_coverage: SPECIFIC_TEST := $(if $(k),-k=$(k))
_test_with_coverage: pyspec
	@$(PYTHON_VENV) -m pytest \
		$(SPECIFIC_TEST) \
		-n auto \
		--disable-bls \
		$(COVERAGE_SCOPE) \
		--cov-report="html:$(COV_HTML_OUT)" \
		--cov-branch \
		$(PY_SPEC_DIR)/eth2spec

# To only run a specific test, do:
#   k=<test> make coverage
# For example:
#   k=test_verify_kzg_proof make coverage
coverage: _test_with_coverage
	@echo "Opening result: $(COV_INDEX_FILE)"
	@((open "$(COV_INDEX_FILE)" || xdg-open "$(COV_INDEX_FILE)") &> /dev/null) &

###############################################################################
# Documentation
###############################################################################

DOCS_DIR = ./docs
FORK_CHOICE_DIR = ./fork_choice
SPEC_DIR = ./specs
SSZ_DIR = ./ssz
SYNC_DIR = ./sync

# Start a local documentation server.
serve_docs:
	@cp -r $(SPEC_DIR) $(DOCS_DIR)
	@cp -r $(SYNC_DIR) $(DOCS_DIR)
	@cp -r $(SSZ_DIR) $(DOCS_DIR)
	@cp -r $(FORK_CHOICE_DIR) $(DOCS_DIR)
	@cp $(CURDIR)/README.md $(DOCS_DIR)/README.md
	@mkdocs build
	@mkdocs serve

###############################################################################
# Checks
###############################################################################

LINTER_CONFIG_FILE = $(CURDIR)/linter.ini
PYLINT_SCOPE := $(foreach S,$(ALL_EXECUTABLE_SPEC_NAMES), $(PY_SPEC_DIR)/eth2spec/$S)
MYPY_SCOPE := $(foreach S,$(ALL_EXECUTABLE_SPEC_NAMES), -p eth2spec.$S)
TEST_GENERATORS_DIR = ./tests/generators
MARKDOWN_FILES = $(wildcard $(SPEC_DIR)/*/*.md) \
                 $(wildcard $(SPEC_DIR)/*/*/*.md) \
                 $(wildcard $(SPEC_DIR)/_features/*/*.md) \
                 $(wildcard $(SPEC_DIR)/_features/*/*/*.md) \
                 $(wildcard $(SSZ_DIR)/*.md)

# Check an individual file. 
%.toc:
	@cp $* $*.tmp && \
	doctoc $* && \
	diff -q $* $*.tmp && \
	rm $*.tmp

# Ensure the table of contents are good.
check_toc: $(MARKDOWN_FILES:=.toc)

# Check for typos.
codespell:
	@codespell . --skip "./.git,./venv,$(PY_SPEC_DIR)/.mypy_cache" -I .codespell-whitelist

# Check for mistakes.
lint: pyspec
	@flake8 --config $(LINTER_CONFIG_FILE) $(PY_SPEC_DIR)/eth2spec
	@flake8 --config $(LINTER_CONFIG_FILE) $(TEST_GENERATORS_DIR)
	@$(PYTHON_VENV) -m pylint --rcfile $(LINTER_CONFIG_FILE) $(PYLINT_SCOPE)
	@$(PYTHON_VENV) -m mypy --config-file $(LINTER_CONFIG_FILE) $(MYPY_SCOPE)

###############################################################################
# Deposit Contract
###############################################################################

export DAPP_SKIP_BUILD:=1
export DAPP_SRC:=$(SOLIDITY_DEPOSIT_CONTRACT_DIR)
export DAPP_LIB:=$(SOLIDITY_DEPOSIT_CONTRACT_DIR)/lib
export DAPP_JSON:=build/combined.json

SOLIDITY_DEPOSIT_CONTRACT_DIR = ./solidity_deposit_contract
SOLIDITY_DEPOSIT_CONTRACT_SOURCE = ${SOLIDITY_DEPOSIT_CONTRACT_DIR}/deposit_contract.sol
SOLIDITY_FILE_NAME = deposit_contract.json
DEPOSIT_CONTRACT_TESTER_DIR = ${SOLIDITY_DEPOSIT_CONTRACT_DIR}/web3_tester

# Compile the deposit contract.
compile_deposit_contract:
	@cd $(SOLIDITY_DEPOSIT_CONTRACT_DIR)
	@git submodule update --recursive --init
	@solc --metadata-literal --optimize --optimize-runs 5000000 --bin --abi \
		--combined-json=abi,bin,bin-runtime,srcmap,srcmap-runtime,ast,metadata,storage-layout \
		--overwrite -o build $(SOLIDITY_DEPOSIT_CONTRACT_SOURCE) \
		$(SOLIDITY_DEPOSIT_CONTRACT_DIR)/tests/deposit_contract.t.sol
	@/bin/echo -n '{"abi": ' > $(SOLIDITY_FILE_NAME)
	@cat build/DepositContract.abi >> $(SOLIDITY_FILE_NAME)
	@/bin/echo -n ', "bytecode": "0x' >> $(SOLIDITY_FILE_NAME)
	@cat build/DepositContract.bin >> $(SOLIDITY_FILE_NAME)
	@/bin/echo -n '"}' >> $(SOLIDITY_FILE_NAME)

# Fuzz the deposit contract a little.
test_deposit_contract:
	@dapp test -v --fuzz-runs 5

# Install the web3 tester.
_install_deposit_contract_web3_tester:
	@cd $(DEPOSIT_CONTRACT_TESTER_DIR); \
	python3 -m venv venv; \
	source venv/bin/activate; \
	python3 -m pip install -r requirements.txt

# Run the web3 tests.
test_deposit_contract_web3_tests: _install_deposit_contract_web3_tester
	@cd $(DEPOSIT_CONTRACT_TESTER_DIR); \
	source venv/bin/activate; \
	python3 -m pytest .

###############################################################################
# Generators
###############################################################################

TEST_VECTOR_DIR = $(CURDIR)/../consensus-spec-tests/tests
GENERATOR_DIR = $(CURDIR)/tests/generators
SCRIPTS_DIR = $(CURDIR)/scripts
GENERATOR_ERROR_LOG_FILE = $(TEST_VECTOR_DIR)/testgen_error_log.txt
GENERATORS = $(sort $(dir $(wildcard $(GENERATOR_DIR)/*/.)))
GENERATOR_TARGETS = $(patsubst $(GENERATOR_DIR)/%/, gen_%, $(GENERATORS)) gen_kzg_setups

# List available generators.
gen_list:
	@for target in $(shell echo $(GENERATOR_TARGETS) | tr ' ' '\n' | sort -n); do \
		echo $$target; \
	done

# Run one generator.
gen_%: pyspec
	@mkdir -p $(TEST_VECTOR_DIR)
	@$(PYTHON_VENV) $(GENERATOR_DIR)/$*/main.py -o $(TEST_VECTOR_DIR); \

# Generate KZG setups.
gen_kzg_setups: $(VENV)
	@for preset in minimal mainnet; do \
		$(PYTHON_VENV) $(SCRIPTS_DIR)/gen_kzg_trusted_setups.py \
			--secret=1337 \
			--g1-length=4096 \
			--g2-length=65 \
			--output-dir $(CURDIR)/presets/$$preset/trusted_setups; \
	done

# Run all generators.
gen_all: $(GENERATOR_TARGETS)

# Detect errors in generators.
gen_error: $(TEST_VECTOR_DIR)
	@find $(TEST_VECTOR_DIR) -name "INCOMPLETE"
	@if [ -f $(GENERATOR_ERROR_LOG_FILE) ]; then \
		echo "[ERROR] $(GENERATOR_ERROR_LOG_FILE) file exists"; \
	else \
		echo "[PASSED] error log file does not exist"; \
	fi

###############################################################################
# Cleaning
###############################################################################

# Delete all untracked files.
clean:
	@git clean -fdx