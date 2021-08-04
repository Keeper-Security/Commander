PYTHON_FILES := ${shell find . -name '*.py' -print}

go2: tags
	# python3 -m pudb keeper.py
	python3 keeper.py

tags: ${PYTHON_FILES}
	ctags ${PYTHON_FILES}

report:
	# pylint $$(find . -name '*.py' -print | sort -R) | ./desired-pylint-warnings
	pylint ${PYTHON_FILES} || true

clean:
	rm -f tags
