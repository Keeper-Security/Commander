PYTHON_FILES := ${shell find . -name '*.py' -print}

go2: tags targeted-report
	python3 -m pytest -s tests/test_vault_commands.py
	# python3 -m pytest -s unit-tests/test_subfolder.py
	# PYTHONPATH=. python3 -m pudb unit-tests/test_subfolder.py
	# python3 -m pytest unit-tests/test_command_folder.py
	# python3 -m pudb keeper.py
	python3 keeper.py

tags: ${PYTHON_FILES}
	# Create the tags file, for the benefit of vi/vim/neovim.
	ctags ${PYTHON_FILES}

.PHONY: targeted-report
targeted-report:
	# This is only checking things that have passed pylint previously - or are currently being made pylint-conformant.
	python3 -m pylint ./keepercommander/importer/imp_exp.py ./keepercommander/ttk.py

cc-report:
	# Generate a cyclomatic (McCabe) complexity report
	python3 -m radon cc $(find keepercommander -type f -name '*.py' -print)

report:
	# pylint all the .py's.
	# pylint $$(find . -name '*.py' -print | sort -R) | ./desired-pylint-warnings
	pylint ${PYTHON_FILES} || true

clean:
	rm -f tags
