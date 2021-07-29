go2: tags
	python3 -m pudb keeper.py
	# python3 keeper.py

tags:
	ctags $$(find * -name '*.py' -print)

go:
	# pylint $$(find . -name '*.py' -print | sort -R) | ./desired-pylint-warnings
	pylint $$(find . -name '*.py' -print)

clean:
	rm -f tags
	find . -type f -name '*.pyc' -print0 | xargs -0 rm -fv
