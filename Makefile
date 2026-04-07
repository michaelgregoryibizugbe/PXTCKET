.PHONY: run install test lint clean help

help:
	@echo ""
	@echo "  Advanced Packet Analyzer — Commands"
	@echo "  ════════════════════════════════════"
	@echo "  make install    Install all dependencies"
	@echo "  make run        Run the TUI (requires sudo)"
	@echo "  make test       Run test suite"
	@echo "  make lint       Run linter"
	@echo "  make clean      Remove generated files"
	@echo ""

install:
	pip install -r requirements.txt

run:
	sudo python main.py

run-no-root:
	python main.py --read /dev/null

test:
	pytest tests/ -v --tb=short --cov=analyzer --cov-report=term-missing

test-fast:
	pytest tests/ -x -q

lint:
	python -m py_compile main.py
	python -m py_compile ai/assistant.py
	find analyzer/ -name "*.py" -exec python -m py_compile {} \;
	find tui/ -name "*.py" -exec python -m py_compile {} \;

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	rm -rf .pytest_cache .coverage htmlcov

clean-all: clean
	rm -f logs/*.log reports/*.json reports/*.csv reports/*.html captures/*.pcap
