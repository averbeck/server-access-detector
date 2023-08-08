PYTHON ?= python3

BUILD_DIR := ./build
DIST_DIR := ./dist
SRC_DIR := ./server_access_detector
NUITKA_CACHE_DIR := ./cache

VENV := ./venv
VENV_ACTIVATE := $(VENV)/bin/activate
VENV_DEV_MARKER := $(VENV)/development
VENV_MARKER := $(VENV)/base

SRC := $(shell find "$(SRC_DIR)" -type f -name '*.py')

BUILD_CONTAINER_NAME := nuitka-builder-$(APP_NAME)
PYTHON_MAJOR = $(shell $(PYTHON) --version | cut -f2 -d" " | cut -f1-2 -d".")
VENV_SM_LINK = $(VENV)/lib/python$(PYTHON_MAJOR)/site-packages/system_manager.pth

DEBIAN_PKGNAME := $(APP_NAME)
DEBIAN_VERSION := $(subst +,.,$(VERSION))
DEBIAN_LICENSE := $(LICENSE)
DEBIAN_DESCR := $(DESCRIPTION)
DEBIAN_ARCH := $(shell dpkg --print-architecture || arch)
DEBIAN_MAINTAINER := $(AUTHOR)
DEBIAN_PACKAGE := $(DEBIAN_PKGNAME)_$(DEBIAN_VERSION)_$(DEBIAN_ARCH).deb
DEBIAN_BUILD_DIR := $(BUILD_DIR)/$(DEBIAN_PACKAGE:.deb=)
DEBIAN_EXTRA_DEPENDENCIES := ""

BIN := $(DIST_DIR)/$(APP_NAME)_$(VERSION)
DEB := $(DIST_DIR)/$(DEBIAN_PACKAGE)
WHEEL := $(DISTDIR)/$(APP_NAME)-$(VERSION)-py3-none-any.whl

export SOURCE_DATE_EPOCH ?= $(shell git log --pretty='%ct' -n1 HEAD || echo 0)

default: build-deb-in-docker

.PHONY: clean-pyc
clean-pyc:
	rm -rf __pycache__ */__pycache__  */*/__pycache__ */*/*/__pycache__

.PHONY: clean
clean: clean-pyc
	-deactivate
	rm -rf $(VENV)
	rm -rf $(BUILD_DIR)
	rm -fr docs/reports/tests/*

.PHONY: clean-full
clean-full: clean
	rm -rf $(DIST_DIR) $(NUITKA_CACHE_DIR)
	rm -rf .eggs *.egg-info */*.egg-info */*/*.egg-info
	rm -rf .pytest_cache
	rm -rf licenses-storage

$(VENV_ACTIVATE):
	$(PYTHON) -m venv $(VENV)

.PHONY: venv
venv: $(VENV_MARKER)

$(VENV_MARKER): $(VENV_ACTIVATE)
	rm -f $(VENV_DEV_MARKER)
	. $(VENV_ACTIVATE) && $(PYTHON) -m pip install -e .
	touch $(VENV_MARKER)

.PHONY: venv-dev
venv-dev: $(VENV_DEV_MARKER)

$(VENV_DEV_MARKER): $(VENV_ACTIVATE) $(VENV_MARKER)
	. $(VENV_ACTIVATE) && $(PYTHON) -m pip install -e .[dev]
	touch $(VENV_DEV_MARKER)

requirements.txt: pyproject.toml
	. $(VENV)/bin/activate && $(PYTHON) -m pip freeze --exclude system_manager > $(@)

.PHONY: wheel
wheel: $(WHEEL)

$(WHEEL): $(SRC)
	$(PYTHON) -m pip wheel -w $(DIST_DIR) .

.PHONY: bin
bin: $(BIN)

# Build frozen binary executable
$(BIN): $(VENV_DEV_MARKER) $(SRC)
# Edit requirements for in-container build
	echo "Building $(@) ..."
	echo "__version__ = \"$(VERSION)\"" > $(SRC_DIR)/utils/__version__.py
	. $(VENV)/bin/activate && NUITKA_CACHE_DIR=$(NUITKA_CACHE_DIR) $(PYTHON) -m nuitka \
		--show-progress \
		--show-modules \
		--follow-imports \
		--static-libpython=no \
		--output-dir="$(BUILD_DIR)" \
		"$(SRC_DIR)/main.py"
	chmod +x $(BUILD_DIR)/main.bin
	ls -lAh $(BUILD_DIR)
	ldd $(BUILD_DIR)/main.bin
# Distribute binary
	mkdir -p $(DIST_DIR)
	mv $(BUILD_DIR)/main.bin $(BIN)

.PHONY: deb
deb: $(DEB)

$(DEB): $(BIN)
	rm -rf $(DEBIAN_BUILD_DIR)
# Create control file for deb package
	mkdir -p $(DEBIAN_BUILD_DIR)/DEBIAN
	printf '%s\n' \
		"Package: $(DEBIAN_PKGNAME)" \
		"Version: $(DEBIAN_VERSION)" \
		"Section: admin" \
		"Priority: optional" \
		"Architecture: $(DEBIAN_ARCH)" \
		"License: $(DEBIAN_LICENSE)" \
		"Maintainer: $(DEBIAN_MAINTAINER)" \
		"Depends: python3 (>= 3.10)$(shell [ -n "$(DEBIAN_EXTRA_DEPENDENCIES)" ] && echo ", $(DEBIAN_EXTRA_DEPENDENCIES)")" \
		"Installed-Size: $$(du -s -k "${DEBIAN_BUILD_DIR}"/ | cut -f1)" \
		"Homepage: www.bitmotec.com" \
		"Description: $(DEBIAN_DESCR)" \
		> $(DEBIAN_BUILD_DIR)/DEBIAN/control
# Build deb package
	mkdir -p "${DEBIAN_BUILD_DIR}/usr/bin/"
	cp "$(BIN)" "${DEBIAN_BUILD_DIR}/usr/bin/${APP_NAME}"
	dpkg-deb \
		--build \
		--root-owner-group \
		$(DEBIAN_BUILD_DIR) \
		$(@)

.PHONY: debug
debug:
	echo "Version: ${VERSION}"

.PHONY: build-docker
build-docker: create-container-image

create-container-image: container/containerfile $(BIN)
	docker build -f container/containerfile \
		--build-arg BINARY=$(BIN) \
		-t bitmotec/$(APP_NAME):latest \
		-t bitmotec/$(APP_NAME):${VERSION} \
		.

.PHONY: check
check: unittests

.PHONY: unittests
unittests: export PROJECT_DIR = $(shell pwd)
unittests: $(VENV_DEV_MARKER) $(SRC)
	mkdir -p docs/reports/tests
	rm -f /tmp/unittest.txt
	. $(VENV)/bin/activate && $(PYTHON) -m nose2 \
		--start-dir tests \
		--plugin nose2.plugins.junitxml \
		--junit-xml \
		--junit-xml-path docs/reports/tests/test_results.xml \
		--with-coverage \
		--coverage-config .coveragerc \
		--coverage-report xml \
		--coverage-report term

.PHONY: fmt
fmt:
	black $(SRC)

.PHONY: install-system-deps
install-system-deps:
	sudo apt update && sudo apt install -y --no-install-recommends libpcap-dev
	