go:
	# pylint $$(find . -name '*.py' -print | sort -R) | ./desired-pylint-warnings
	pylint $$(find . -name '*.py' -print)
