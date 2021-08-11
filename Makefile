PYTHON_FILES := ${shell find . -name '*.py' -print}

go2: tags
	python3 keeper.py --login-v3 false  # v2 login
	# python3 keeper.py  # v3 login

go2: tags targeted-report
	python3 -m pudb keeper.py
	# python3 keeper.py

tags: ${PYTHON_FILES}
	# Create the tags file, for the benefit of vi/vim/neovim.
	ctags ${PYTHON_FILES}

.PHONY: targeted-report
targeted-report:
	# This is only checking things that have passed pylint previously - or are currently being made pylint-conformant.
	python3 -m pylint ./keepercommander/importer/imp_exp.py

report:
	# pylint all the .py's.
	# pylint $$(find . -name '*.py' -print | sort -R) | ./desired-pylint-warnings
	pylint ${PYTHON_FILES} || true

clean:
	rm -f tags
