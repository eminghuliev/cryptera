app:
	python3 setup.py build_ext -i
	pip install .
clean:
	rm -rf *.a *.o *.so *.so.* *.d build/
