go2: tags
	python3 keeper.py

tags:
	ctags $$(find * -name '*.py' -print)

go:
	# pylint $$(find . -name '*.py' -print | sort -R) | ./desired-pylint-warnings
	pylint $$(find . -name '*.py' -print)

clean:
	rm -f tags
